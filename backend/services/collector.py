"""
Central Event Collector Service for NetDecoy
Validates, enriches, persists, and notifies downstream intelligence components.
"""
import json
import logging
from backend.database.db import SessionLocal
from backend.database.models import EventModel
from backend.services.session_service import update_or_create_session
from backend.services.geo_service import get_ip_geo
from backend.utils.helpers import generate_event_id, generate_session_id, current_utc_iso, sanitize_ip

logger = logging.getLogger(__name__)

# Action / Type to default severity mapping
_SEVERITY_MAP = {
    "sql_injection": "CRITICAL",
    "sqli_probe": "CRITICAL",
    "command_injection": "CRITICAL",
    "rce": "CRITICAL",
    "privilege_escalation": "CRITICAL",
    "credential_stuffing": "HIGH",
    "directory_traversal": "HIGH",
    "data_exfiltration": "HIGH",
    "unauthorized_access": "HIGH",
    "failed_login": "MEDIUM",
    "brute_force": "MEDIUM",
    "scanning": "LOW",
    "reconnaissance": "LOW",
    "page_view": "LOW"
}

def derive_severity(action: str, event_type: str, explicit_severity: str = None) -> str:
    """Infer severity level based on action and event type if not explicitly provided."""
    if explicit_severity and explicit_severity.upper() in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        return explicit_severity.upper()

    act = (action or "").lower()
    etype = (event_type or "").lower()

    if act in _SEVERITY_MAP:
        return _SEVERITY_MAP[act]
    if etype in _SEVERITY_MAP:
        return _SEVERITY_MAP[etype]

    if "sql" in act or "inject" in act:
        return "CRITICAL"
    if "admin" in act or "auth" in etype or "login" in act:
        return "MEDIUM"
    return "LOW"

def log_event(
    session_id: str = None,
    source_ip: str = None,
    page: str = None,
    action: str = None,
    event_type: str = None,
    payload: dict = None,
    event_id: str = None,
    timestamp: str = None,
    severity: str = None,
    geo: dict = None
) -> dict:
    """
    Central event collector for all honeypot telemetry.
    Normalizes inputs, enriches metadata, persists to database, and updates sessions.
    """
    try:
        # 1. Normalize and assign defaults
        clean_event_id = event_id or generate_event_id()
        clean_session_id = session_id or generate_session_id()
        clean_timestamp = timestamp or current_utc_iso()
        clean_source_ip = sanitize_ip(source_ip)
        clean_page = page or "unknown_trap"
        clean_action = action or "probe"
        clean_event_type = event_type or "reconnaissance"
        clean_payload = payload if isinstance(payload, dict) else {}
        clean_severity = derive_severity(clean_action, clean_event_type, severity)

        # 2. Geolocation enrichment (fails gracefully)
        if geo is None:
            clean_geo = get_ip_geo(clean_source_ip)
        else:
            clean_geo = geo

        payload_json_str = json.dumps(clean_payload)
        geo_json_str = json.dumps(clean_geo)

        # 3. Persist Event to Database
        db = SessionLocal()
        try:
            event_entry = EventModel(
                event_id=clean_event_id,
                session_id=clean_session_id,
                timestamp=clean_timestamp,
                source_ip=clean_source_ip,
                page=clean_page,
                action=clean_action,
                event_type=clean_event_type,
                severity=clean_severity,
                payload_json=payload_json_str,
                geo_json=geo_json_str
            )
            db.add(event_entry)
            db.commit()
            persisted_dict = event_entry.to_dict()
        except Exception as db_err:
            db.rollback()
            logger.error(f"Failed to persist event {clean_event_id}: {db_err}")
            persisted_dict = {
                "event_id": clean_event_id,
                "session_id": clean_session_id,
                "timestamp": clean_timestamp,
                "source_ip": clean_source_ip,
                "page": clean_page,
                "action": clean_action,
                "event_type": clean_event_type,
                "severity": clean_severity,
                "payload": clean_payload,
                "geo": clean_geo
            }
        finally:
            db.close()

        # 4. Update Session Tracking
        update_or_create_session(
            session_id=clean_session_id,
            source_ip=clean_source_ip,
            timestamp=clean_timestamp
        )

        return persisted_dict

    except Exception as e:
        logger.error(f"Critical error in log_event: {e}", exc_info=True)
        # Never crash callers
        return {
            "event_id": event_id or generate_event_id(),
            "session_id": session_id or "sess_fallback",
            "timestamp": timestamp or current_utc_iso(),
            "source_ip": source_ip or "127.0.0.1",
            "page": page or "error_fallback",
            "action": action or "error",
            "event_type": event_type or "system",
            "severity": "LOW",
            "payload": payload or {},
            "geo": {"available": False, "message": "Collector fallback"}
        }
