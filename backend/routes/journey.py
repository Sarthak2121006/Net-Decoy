"""
Attacker Journey Route (GET /api/journey)
"""
from flask import Blueprint, request, jsonify
from backend.services.session_service import build_session_journey
import logging

logger = logging.getLogger(__name__)
journey_bp = Blueprint("journey", __name__)

@journey_bp.route("/api/journey", methods=["GET"])
def get_journey():
    """
    Return ordered attack stages and progression for an attacker journey.
    """
    try:
        session_id = request.args.get("session_id")
        stages = build_session_journey(session_id=session_id)
        return jsonify({
            "status": "success",
            "session_id": session_id or "all_sessions",
            "stages": stages
        }), 200
    except Exception as e:
        logger.error(f"Error fetching journey: {e}")
        return jsonify({
            "status": "error",
            "session_id": session_id or "unknown",
            "stages": []
        }), 200
