"""
Next-Stage Attack Prediction Route (GET /api/prediction)
"""
from flask import Blueprint, request, jsonify
from backend.services.intelligence_bridge import predict_next_stage
import logging

logger = logging.getLogger(__name__)
prediction_bp = Blueprint("prediction", __name__)

@prediction_bp.route("/api/prediction", methods=["GET"])
def get_prediction():
    """
    Return predicted next adversary step and confidence score.
    """
    try:
        session_id = request.args.get("session_id")
        prediction_data = predict_next_stage(session_id=session_id)
        return jsonify(prediction_data), 200
    except Exception as e:
        logger.error(f"Error getting attack prediction: {e}")
        return jsonify({
            "next_stage": "Reconnaissance",
            "confidence": 50,
            "basis": "Default baseline heuristic"
        }), 200
