"""
Session Tracking and Management Service
"""
from backend.database.db import SessionLocal
from backend.database.models import SessionModel, EventModel
from backend.utils.helpers import current_utc_iso
import logging

logger = logging.getLogger(__name__)

def update_or_create_session(session_id: str, source_ip: str, timestamp: str = None) -> dict:
    """
    Update an existing session's last_seen and event count, or create a new session.
    """
    ts = timestamp or current_utc_iso()
    db = SessionLocal()
    try:
        session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
        if session:
            session.last_seen = ts
            session.event_count += 1
            if source_ip:
                session.source_ip = source_ip
            db.commit()
            return session.to_dict()
        else:
            new_session = SessionModel(
                session_id=session_id,
                source_ip=source_ip or "127.0.0.1",
                first_seen=ts,
                last_seen=ts,
                event_count=1,
                risk_score=0,
                risk_level="LOW",
                status="active"
            )
            db.add(new_session)
            db.commit()
            return new_session.to_dict()
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating session {session_id}: {e}")
        return {
            "session_id": session_id,
            "source_ip": source_ip,
            "first_seen": ts,
            "last_seen": ts,
            "event_count": 1,
            "risk_score": 0,
            "risk_level": "LOW",
            "status": "active"
        }
    finally:
        db.close()

def get_session(session_id: str) -> dict:
    """Retrieve session details by ID."""
    db = SessionLocal()
    try:
        session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
        if session:
            return session.to_dict()
        return None
    finally:
        db.close()

def get_all_sessions(limit: int = 100) -> list:
    """Retrieve all sessions ordered by last_seen descending."""
    db = SessionLocal()
    try:
        sessions = db.query(SessionModel).order_by(SessionModel.last_seen.desc()).limit(limit).all()
        return [s.to_dict() for s in sessions]
    finally:
        db.close()

def build_session_journey(session_id: str = None) -> list:
    """
    Reconstruct attacker journey stages in chronological order.
    """
    db = SessionLocal()
    try:
        query = db.query(EventModel)
        if session_id:
            query = query.filter(EventModel.session_id == session_id)
        events = query.order_by(EventModel.timestamp.asc()).all()

        stages = []
        for evt in events:
            # Map event type and action to attack stage
            stage_name = "Reconnaissance"
            if evt.event_type in ["authentication", "credential_stuffing"]:
                stage_name = "Initial Access"
            elif evt.event_type in ["exploitation", "sql_injection", "command_injection"]:
                stage_name = "Exploitation"
            elif evt.event_type in ["privilege_escalation"]:
                stage_name = "Privilege Escalation"
            elif evt.event_type in ["data_exfiltration"]:
                stage_name = "Data Exfiltration"

            desc = f"Action '{evt.action}' on trap page '{evt.page}' [{evt.severity}]"
            stages.append({
                "stage": stage_name,
                "event_id": evt.event_id,
                "session_id": evt.session_id,
                "timestamp": evt.timestamp,
                "page": evt.page,
                "action": evt.action,
                "severity": evt.severity,
                "description": desc
            })
        return stages
    finally:
        db.close()
