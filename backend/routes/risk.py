"""
Risk Assessment Route (GET /api/risk)
"""
from flask import Blueprint, request, jsonify
from backend.services.intelligence_bridge import calculate_risk
import logging

logger = logging.getLogger(__name__)
risk_bp = Blueprint("risk", __name__)

@risk_bp.route("/api/risk", methods=["GET"])
def get_risk():
    """
    Return global or session-specific risk score and attack breakdown.
    """
    try:
        session_id = request.args.get("session_id")
        risk_data = calculate_risk(session_id=session_id)
        return jsonify(risk_data), 200
    except Exception as e:
        logger.error(f"Error getting risk data: {e}")
        return jsonify({
            "score": 0,
            "level": "LOW",
            "breakdown": {
                "brute_force": 0,
                "scanning": 0,
                "sql_injection": 0,
                "directory_traversal": 0
            }
        }), 200
