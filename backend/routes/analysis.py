"""
AI Analysis & Threat Intelligence Route (GET /api/analysis)
"""
from flask import Blueprint, request, jsonify
from backend.services.intelligence_bridge import get_ai_analysis
import logging

logger = logging.getLogger(__name__)
analysis_bp = Blueprint("analysis", __name__)

@analysis_bp.route("/api/analysis", methods=["GET"])
def get_analysis():
    """
    Return AI-generated threat actor profile, summary analysis, and recommendations.
    """
    try:
        session_id = request.args.get("session_id")
        analysis = get_ai_analysis(session_id=session_id)
        return jsonify(analysis), 200
    except Exception as e:
        logger.error(f"Error fetching AI analysis: {e}")
        return jsonify({
            "status": "error",
            "analysis": "Intelligence analysis temporarily unavailable.",
            "threat_actor_profile": "Unknown",
            "recommendations": []
        }), 200
