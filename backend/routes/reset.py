"""
Demo State Reset Route (POST /api/reset)
"""
from flask import Blueprint, jsonify
from backend.database.db import reset_db
from backend.services.geo_service import clear_geo_cache
import logging

logger = logging.getLogger(__name__)
reset_bp = Blueprint("reset", __name__)

@reset_bp.route("/api/reset", methods=["POST"])
def reset_state():
    """
    Clear all events and sessions, restoring the database to a clean initial state.
    """
    try:
        reset_db()
        clear_geo_cache()
        logger.info("Demo database and state successfully reset.")
        return jsonify({
            "status": "success",
            "message": "Demo state reset successfully"
        }), 200
    except Exception as e:
        logger.error(f"Error resetting database: {e}")
        return jsonify({
            "status": "error",
            "message": f"Reset failed: {str(e)}"
        }), 500
