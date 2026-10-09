"""
Intelligence Bridge for NetDecoy
Integrates M3 detection algorithms with resilient built-in heuristics fallback.
"""
import logging
import importlib
from backend.database.db import SessionLocal
from backend.database.models import EventModel, SessionModel

logger = logging.getLogger(__name__)

def _get_m3_engine():
    """Attempt to dynamically load M3 intelligence module if available."""
    try:
        m3 = importlib.import_module("intelligence.engine")
        return m3
    except Exception:
        try:
            m3 = importlib.import_module("intelligence")
            return m3
        except Exception:
            return None

def calculate_risk(session_id: str = None) -> dict:
    """
    Calculate risk score, severity level, and attack breakdown.
    Delegates to M3 if available, otherwise executes standard heuristic engine.
    """
    m3 = _get_m3_engine()
    if m3 and hasattr(m3, "calculate_risk"):
        try:
            return m3.calculate_risk(session_id)
        except Exception as e:
            logger.warning(f"M3 calculate_risk failed, falling back to heuristics: {e}")

    db = SessionLocal()
    try:
        query = db.query(EventModel)
        if session_id:
            query = query.filter(EventModel.session_id == session_id)
        events = query.all()

        if not events:
            return {
                "score": 0,
                "level": "LOW",
                "breakdown": {
                    "brute_force": 0,
                    "scanning": 0,
                    "sql_injection": 0,
                    "directory_traversal": 0
                }
            }

        breakdown = {
            "brute_force": 0,
            "scanning": 0,
            "sql_injection": 0,
            "directory_traversal": 0
        }

        severity_weights = {
            "LOW": 5,
            "MEDIUM": 15,
            "HIGH": 30,
            "CRITICAL": 50
        }

        total_weight = 0
        for evt in events:
            # Map action/type to category breakdown
            act = evt.action.lower()
            etype = evt.event_type.lower()
            
            if "sqli" in act or "sql" in etype or "sql_injection" in act:
                breakdown["sql_injection"] += 1
            elif "scan" in act or "scan" in etype or "probe" in act or "enum" in act:
                breakdown["scanning"] += 1
            elif "brute" in act or "failed_login" in act or "auth" in etype:
                breakdown["brute_force"] += 1
            elif "traversal" in act or "path" in act or "env" in act:
                breakdown["directory_traversal"] += 1
            else:
                breakdown["scanning"] += 1

            total_weight += severity_weights.get(evt.severity.upper(), 5)

        # Normalize score between 0 and 100
        # More events and higher severities escalate risk rapidly
        raw_score = min(100, int(total_weight * 1.5))
        if len(events) >= 1 and raw_score == 0:
            raw_score = 10

        if raw_score >= 80:
            level = "CRITICAL"
        elif raw_score >= 60:
            level = "HIGH"
        elif raw_score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "score": raw_score,
            "level": level,
            "breakdown": breakdown
        }
    finally:
        db.close()

def predict_next_stage(session_id: str = None) -> dict:
    """
    Predict attacker's next anticipated attack stage and confidence.
    """
    m3 = _get_m3_engine()
    if m3 and hasattr(m3, "predict_next_stage"):
        try:
            return m3.predict_next_stage(session_id)
        except Exception as e:
            logger.warning(f"M3 predict_next_stage failed, falling back: {e}")

    db = SessionLocal()
    try:
        query = db.query(EventModel)
        if session_id:
            query = query.filter(EventModel.session_id == session_id)
        events = query.order_by(EventModel.timestamp.desc()).limit(10).all()

        if not events:
            return {
                "next_stage": "Initial Reconnaissance",
                "confidence": 50,
                "basis": "No telemetry captured yet. Awaiting initial probes."
            }

        last_event = events[0]
        event_types = [e.event_type.lower() for e in events]
        actions = [e.action.lower() for e in events]

        if any("sql" in t or "injection" in a for t, a in zip(event_types, actions)):
            return {
                "next_stage": "Privilege Escalation",
                "confidence": 84,
                "basis": "SQL injection attempts observed. Attacker likely probing for administrative table hashes."
            }
        elif any("auth" in t or "login" in a for t, a in zip(event_types, actions)):
            return {
                "next_stage": "Credential Stuffing & Session Hijacking",
                "confidence": 75,
                "basis": "Repeated authentication failures detected across trap gateways."
            }
        elif any("traversal" in a or "env" in a for a in actions):
            return {
                "next_stage": "Sensitive File Exfiltration",
                "confidence": 78,
                "basis": "Directory traversal payload detected targeting configuration keys."
            }
        else:
            return {
                "next_stage": "Vulnerability Probing",
                "confidence": 65,
                "basis": "Automated port and endpoint scanner signatures identified."
            }
    finally:
        db.close()

def get_ai_analysis(session_id: str = None) -> dict:
    """
    Retrieve or generate contextual AI threat intelligence summary.
    """
    m3 = _get_m3_engine()
    if m3 and hasattr(m3, "get_analysis"):
        try:
            return m3.get_analysis(session_id)
        except Exception as e:
            logger.warning(f"M3 get_analysis failed, falling back: {e}")

    risk = calculate_risk(session_id)
    pred = predict_next_stage(session_id)

    db = SessionLocal()
    try:
        query = db.query(EventModel)
        if session_id:
            query = query.filter(EventModel.session_id == session_id)
        count = query.count()

        if count == 0:
            return {
                "status": "success",
                "analysis": "Honeypot telemetry active. Decoy sensors waiting for adversary interaction.",
                "threat_actor_profile": "Unclassified / Idle",
                "recommendations": [
                    "Ensure all 6 trap endpoints are active and routing telemetry",
                    "Monitor real-time collector log stream"
                ]
            }

        analysis_text = (
            f"Adversary activity detected with risk index of {risk['score']}/100 ({risk['level']}). "
            f"Observed pattern correlates with {pred['next_stage'].lower()} tactics. "
            f"Telemetry shows elevated activity across {count} logged interaction events."
        )

        threat_profile = "Automated Exploitation Script" if risk["score"] > 60 else "Reconnaissance Bot"
        recommendations = [
            f"Apply honeypot rate-limiting to source IPs",
            f"Deploy decoy credential canary tokens for {pred['next_stage']}",
            f"Extract attacker payload patterns into detection rules"
        ]

        return {
            "status": "success",
            "analysis": analysis_text,
            "threat_actor_profile": threat_profile,
            "recommendations": recommendations
        }
    finally:
        db.close()
