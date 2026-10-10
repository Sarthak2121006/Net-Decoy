"""
IP Geolocation Route (GET /api/geo)
"""
from flask import Blueprint, request, jsonify
from backend.services.geo_service import get_ip_geo
from backend.database.db import SessionLocal
from backend.database.models import EventModel
import logging

logger = logging.getLogger(__name__)
geo_bp = Blueprint("geo", __name__)

def get_real_client_ip():

    """Extract real client IP behind reverse proxies (Render, Cloudflare, Nginx)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[0]
    real_ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.remote_addr or "127.0.0.1"


@geo_bp.route("/api/geo", methods=["GET"])
def get_geo():
    """
    Return approximate geographic information for an IP address.
    If no IP is passed, falls back to latest attacker IP or request client IP.
    """
    try:
        ip = request.args.get("ip")
        if not ip:
            # Try to grab IP from most recent event
            db = SessionLocal()
            try:
                latest_event = db.query(EventModel).order_by(EventModel.timestamp.desc()).first()
                if latest_event and latest_event.source_ip:
                    ip = latest_event.source_ip
            finally:
                db.close()

        if not ip or ip in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
            ip = get_real_client_ip()


        geo_data = get_ip_geo(ip)
        return jsonify(geo_data), 200
    except Exception as e:
        logger.error(f"Error resolving geo: {e}")
        return jsonify({
            "available": False,
            "message": "Location unavailable"
        }), 200
