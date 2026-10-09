"""
Attacker Session Management Routes (GET /api/sessions, GET /api/sessions/<session_id>)
"""
from flask import Blueprint, request, jsonify
from backend.services.session_service import get_all_sessions, get_session, build_session_journey
from backend.services.intelligence_bridge import calculate_risk, predict_next_stage, get_ai_analysis
import logging

logger = logging.getLogger(__name__)
sessions_bp = Blueprint("sessions", __name__)

@sessions_bp.route("/api/sessions", methods=["GET"])
def list_sessions():
    """
    List all tracked attacker sessions with event counts and risk scores.
    """
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        sessions = get_all_sessions(limit=limit)

        # Enrich each session with current risk level
        for s in sessions:
            risk = calculate_risk(session_id=s["session_id"])
            s["risk_score"] = risk["score"]
            s["risk_level"] = risk["level"]

        return jsonify({
            "status": "success",
            "count": len(sessions),
            "sessions": sessions
        }), 200
    except Exception as e:
        logger.error(f"Error listing sessions: {e}")
        return jsonify({"status": "error", "message": "Failed to list sessions", "sessions": []}), 500


@sessions_bp.route("/api/sessions/<session_id>", methods=["GET"])
def get_session_detail(session_id):
    """
    Deep dive into a specific attacker session (journey, risk breakdown, AI analysis).
    """
    try:
        sess = get_session(session_id)
        if not sess:
            return jsonify({"status": "error", "message": "Session not found"}), 404

        risk = calculate_risk(session_id=session_id)
        journey = build_session_journey(session_id=session_id)
        prediction = predict_next_stage(session_id=session_id)
        analysis = get_ai_analysis(session_id=session_id)

        sess["risk"] = risk
        sess["journey"] = journey
        sess["prediction"] = prediction
        sess["analysis"] = analysis

        return jsonify({
            "status": "success",
            "session": sess
        }), 200
    except Exception as e:
        logger.error(f"Error fetching session detail for {session_id}: {e}")
        return jsonify({"status": "error", "message": "Failed to fetch session detail"}), 500
