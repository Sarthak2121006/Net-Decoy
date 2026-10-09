"""
Quarantine & Active Defense Routes (GET/POST/DELETE /api/quarantine)
"""
from flask import Blueprint, request, jsonify
from backend.services.quarantine_service import list_quarantined_ips, quarantine_ip, unquarantine_ip
import logging

logger = logging.getLogger(__name__)
quarantine_bp = Blueprint("quarantine", __name__)

@quarantine_bp.route("/api/quarantine", methods=["GET"])
def get_quarantined_ips():
    """List all quarantined attacker IPs."""
    try:
        records = list_quarantined_ips()
        return jsonify({
            "status": "success",
            "count": len(records),
            "quarantined_ips": records
        }), 200
    except Exception as e:
        logger.error(f"Error fetching quarantine list: {e}")
        return jsonify({"status": "error", "quarantined_ips": []}), 500


@quarantine_bp.route("/api/quarantine", methods=["POST"])
def add_to_quarantine():
    """Add an IP address to quarantine."""
    try:
        data = request.get_json(silent=True) or {}
        ip = data.get("ip") or data.get("ip_address")
        reason = data.get("reason", "Manual SOC Defense Action")

        if not ip:
            return jsonify({"status": "error", "message": "Missing 'ip' field"}), 400

        result = quarantine_ip(ip_address=ip, reason=reason)
        return jsonify({
            "status": "success",
            "message": f"IP {ip} quarantined successfully",
            "record": result
        }), 201
    except Exception as e:
        logger.error(f"Error adding IP to quarantine: {e}")
        return jsonify({"status": "error", "message": "Failed to quarantine IP"}), 500


@quarantine_bp.route("/api/quarantine/<path:ip>", methods=["DELETE"])
def remove_from_quarantine(ip):
    """Release an IP from quarantine."""
    try:
        success = unquarantine_ip(ip_address=ip)
        if success:
            return jsonify({
                "status": "success",
                "message": f"IP {ip} removed from quarantine"
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": f"IP {ip} was not found in active quarantine"
            }), 404
    except Exception as e:
        logger.error(f"Error removing IP from quarantine: {e}")
        return jsonify({"status": "error", "message": "Failed to unquarantine IP"}), 500
