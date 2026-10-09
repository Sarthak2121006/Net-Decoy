"""
Real-Time Threat Alerting and Incident Notification Service
Generates actionable SOC alerts based on threat velocity, critical payloads, and attack patterns.
"""
from backend.database.db import SessionLocal
from backend.database.models import EventModel, SessionModel
from backend.utils.helpers import current_utc_iso
import logging

logger = logging.getLogger(__name__)

def generate_threat_alerts(limit: int = 20) -> list:
    """
    Evaluate recent events and trigger structured SOC alerts.
    """
    db = SessionLocal()
    try:
        # Fetch recent high-severity events
        events = db.query(EventModel).order_by(EventModel.timestamp.desc()).limit(100).all()

        alerts = []
        seen_sessions = set()

        for evt in events:
            # Critical Exploit Alerts
            if evt.severity == "CRITICAL":
                alert_id = f"alt_{evt.event_id}"
                alerts.append({
                    "alert_id": alert_id,
                    "timestamp": evt.timestamp,
                    "session_id": evt.session_id,
                    "source_ip": evt.source_ip,
                    "trap_page": evt.page,
                    "severity": "CRITICAL",
                    "title": f"Critical Threat: {evt.action.replace('_', ' ').title()}",
                    "message": f"High-risk action '{evt.action}' executed on trap '{evt.page}' by IP {evt.source_ip}.",
                    "action_required": "Immediate Subnet Quarantine & Token Invalidation"
                })
            
            # High Severity Alerts
            elif evt.severity == "HIGH":
                alerts.append({
                    "alert_id": f"alt_{evt.event_id}",
                    "timestamp": evt.timestamp,
                    "session_id": evt.session_id,
                    "source_ip": evt.source_ip,
                    "trap_page": evt.page,
                    "severity": "HIGH",
                    "title": f"High Suspicion: {evt.action.replace('_', ' ').title()}",
                    "message": f"Suspicious behavior detected on trap '{evt.page}' ({evt.event_type}).",
                    "action_required": "Review session audit logs"
                })

        return alerts[:limit]
    except Exception as e:
        logger.error(f"Error generating threat alerts: {e}")
        return []
    finally:
        db.close()
