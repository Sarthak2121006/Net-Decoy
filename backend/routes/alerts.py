"""
SOC Threat Alerts Route (GET /api/alerts)
"""
from flask import Blueprint, request, jsonify
from backend.services.alert_service import generate_threat_alerts
import logging

logger = logging.getLogger(__name__)
alerts_bp = Blueprint("alerts", __name__)

@alerts_bp.route("/api/alerts", methods=["GET"])
def get_alerts():
    """
    Return recent threat alerts for the SOC dashboard notification center.
    """
    try:
        limit = min(int(request.args.get("limit", 20)), 100)
        alerts = generate_threat_alerts(limit=limit)
        return jsonify({
            "status": "success",
            "count": len(alerts),
            "alerts": alerts
        }), 200
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return jsonify({
            "status": "error",
            "count": 0,
            "alerts": []
        }), 500
