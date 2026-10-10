"""
Events Route Handlers (POST /api/events, GET /api/events)
"""
from flask import Blueprint, request, jsonify
from backend.services.collector import log_event
from backend.database.db import SessionLocal
from backend.database.models import EventModel
import logging

logger = logging.getLogger(__name__)
events_bp = Blueprint("events", __name__)

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


@events_bp.route("/api/events", methods=["POST"])
def ingest_event():
    """
    Ingest a new honeypot telemetry event.
    Accepts JSON body matching shared/event_schema.json.
    """
    try:
        data = request.get_json(silent=True) or {}
        
        # If no IP supplied, or client sent 127.0.0.1/localhost fallback, resolve real IP from request
        client_ip = data.get("source_ip")
        if not client_ip or client_ip in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
            client_ip = get_real_client_ip()

        event = log_event(
            session_id=data.get("session_id"),
            source_ip=client_ip,
            page=data.get("page"),
            action=data.get("action"),
            event_type=data.get("event_type"),
            payload=data.get("payload"),
            event_id=data.get("event_id"),
            timestamp=data.get("timestamp"),
            severity=data.get("severity"),
            geo=data.get("geo")
        )


        return jsonify({
            "status": "success",
            "event": event
        }), 201
    except Exception as e:
        logger.error(f"Error ingesting event: {e}")
        return jsonify({"status": "error", "message": "Failed to ingest event"}), 500


@events_bp.route("/api/events", methods=["GET"])
def get_events():
    """
    Query recent honeypot events with optional filtering.
    """
    try:
        session_id = request.args.get("session_id")
        event_type = request.args.get("event_type")
        severity = request.args.get("severity")
        limit = min(int(request.args.get("limit", 50)), 500)

        db = SessionLocal()
        try:
            query = db.query(EventModel)
            if session_id:
                query = query.filter(EventModel.session_id == session_id)
            if event_type:
                query = query.filter(EventModel.event_type == event_type)
            if severity:
                query = query.filter(EventModel.severity == severity.upper())

            events = query.order_by(EventModel.timestamp.desc()).limit(limit).all()
            result = [e.to_dict() for e in events]

            return jsonify({
                "status": "success",
                "count": len(result),
                "events": result
            }), 200
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error fetching events: {e}")
        return jsonify({"status": "error", "message": "Failed to fetch events", "events": []}), 500
