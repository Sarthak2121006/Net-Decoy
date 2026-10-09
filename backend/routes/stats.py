"""
System & Telemetry Statistics Route (GET /api/stats)
"""
from flask import Blueprint, jsonify
from backend.database.db import SessionLocal
from backend.database.models import EventModel, SessionModel
import logging

logger = logging.getLogger(__name__)
stats_bp = Blueprint("stats", __name__)

@stats_bp.route("/api/stats", methods=["GET"])
def get_stats():
    """
    Return aggregate KPI statistics for dashboard overview.
    """
    db = SessionLocal()
    try:
        total_events = db.query(EventModel).count()
        total_sessions = db.query(SessionModel).count()
        
        # Threats detected: events with severity MEDIUM, HIGH, or CRITICAL
        threats_detected = db.query(EventModel).filter(
            EventModel.severity.in_(["MEDIUM", "HIGH", "CRITICAL"])
        ).count()

        # High risk: events with severity HIGH or CRITICAL
        high_risk = db.query(EventModel).filter(
            EventModel.severity.in_(["HIGH", "CRITICAL"])
        ).count()

        return jsonify({
            "total_events": total_events,
            "total_sessions": total_sessions,
            "threats_detected": threats_detected,
            "high_risk": high_risk
        }), 200
    except Exception as e:
        logger.error(f"Error computing stats: {e}")
        return jsonify({
            "total_events": 0,
            "total_sessions": 0,
            "threats_detected": 0,
            "high_risk": 0
        }), 200
    finally:
        db.close()
