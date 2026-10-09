"""
Attack Clusters & Campaign Correlation Route (GET /api/clusters)
Intelligently groups concurrent and related attack events into structured incident clusters.
"""
from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
from backend.services.intelligence_bridge import _get_session_events
import logging

logger = logging.getLogger(__name__)
clusters_bp = Blueprint("clusters", __name__)

MITRE_CLUSTER_MAPPING = {
    "sql_injection": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application (SQLi)",
        "tactic": "Initial Access / Execution",
        "directive": "Apply parameterized SQL bindings and deploy synthetic SQL response tarpit."
    },
    "brute_force": {
        "id": "T1110.003",
        "name": "Password Spraying & Brute Force",
        "tactic": "Credential Access",
        "directive": "Enforce progressive delay, CAPTCHA challenge, and lock targeted usernames."
    },
    "directory_traversal": {
        "id": "T1083",
        "name": "File and Directory Discovery (Path Traversal)",
        "tactic": "Discovery / Execution",
        "directive": "Canonicalize document lookup paths and return synthetic decoy directory indexes."
    },
    "scanning": {
        "id": "T1046",
        "name": "Network Service & Endpoint Scanning",
        "tactic": "Reconnaissance / Discovery",
        "directive": "Deploy rate-limiting deception tarpits on discovered endpoints."
    },
    "sensitive_access": {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "directive": "Inject watermarked canary tokens into downloaded archive packages and quarantine session."
    },
    "privilege_escalation": {
        "id": "T1078.004",
        "name": "Valid Accounts: Cloud / Admin Role Override",
        "tactic": "Privilege Escalation",
        "directive": "Enforce cryptographic JWT token verification and isolate administrative node access."
    }
}

def _categorize_event(event: dict) -> str:
    act = (event.get("action") or "").lower()
    etype = (event.get("event_type") or "").lower()
    page = (event.get("page") or "").lower()
    payload_str = str(event.get("payload") or "").lower()

    if "sql" in act or etype == "sqli" or etype == "sql_injection" or "select" in payload_str or "union" in payload_str:
        return "sql_injection"
    elif "login" in act or etype == "authentication" or "brute" in act or "password" in payload_str:
        return "brute_force"
    elif "traversal" in act or etype == "traversal" or ".." in payload_str or "passwd" in payload_str or "win.ini" in payload_str:
        return "directory_traversal"
    elif "backup" in act or etype == "sensitive_access" or "exfil" in act or "download" in act:
        return "sensitive_access"
    elif "privilege" in act or etype == "privilege_escalation" or "role" in payload_str:
        return "privilege_escalation"
    else:
        return "scanning"

@clusters_bp.route("/api/clusters", methods=["GET"])
def get_attack_clusters():
    """
    Retrieve aggregated attack clusters grouped by vector, target surface, and threat pattern.
    """
    try:
        session_id = request.args.get("session_id")
        events = _get_session_events(session_id)

        if not events:
            return jsonify({
                "status": "success",
                "total_events": 0,
                "cluster_count": 0,
                "clusters": []
            }), 200

        # Group events by category
        grouped = {}
        for ev in events:
            cat = _categorize_event(ev)
            if cat not in grouped:
                grouped[cat] = []
            grouped[cat].append(ev)

        clusters = []
        cluster_titles = {
            "sql_injection": "SQL Injection Attack Campaign",
            "brute_force": "Credential Brute-Force Spray Cluster",
            "directory_traversal": "Path Traversal & Host Probe Group",
            "scanning": "Reconnaissance & Endpoint Discovery Swarm",
            "sensitive_access": "Storage Vault Exfiltration Campaign",
            "privilege_escalation": "Privilege Escalation & Role Override Probes"
        }

        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        for cat, cat_events in grouped.items():
            # Determine aggregate severity
            highest_sev = "LOW"
            for e in cat_events:
                sev = (e.get("severity") or "LOW").upper()
                if severity_rank.get(sev, 1) > severity_rank.get(highest_sev, 1):
                    highest_sev = sev

            # Extract distinct target routes and source IPs
            target_endpoints = sorted(list(set(f"/{e.get('page', 'trap')}" for e in cat_events)))
            source_ips = sorted(list(set(e.get("source_ip", "127.0.0.1") for e in cat_events)))

            # Timestamps
            timestamps = [e.get("timestamp", "") for e in cat_events if e.get("timestamp")]
            first_seen = min(timestamps) if timestamps else datetime.now(timezone.utc).isoformat()
            last_seen = max(timestamps) if timestamps else datetime.now(timezone.utc).isoformat()

            # Unique payload extractions
            sample_payload = ""
            for e in cat_events:
                p = e.get("payload")
                if p:
                    sample_payload = p
                    break

            mitre = MITRE_CLUSTER_MAPPING.get(cat, MITRE_CLUSTER_MAPPING["scanning"])

            clusters.append({
                "cluster_id": f"cluster_{cat}_{len(cat_events)}",
                "cluster_title": cluster_titles.get(cat, f"{cat.title()} Attack Cluster"),
                "attack_type": cat,
                "event_count": len(cat_events),
                "severity": highest_sev,
                "target_endpoints": target_endpoints,
                "source_ips": source_ips,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "mitre_technique": {
                    "id": mitre["id"],
                    "name": mitre["name"],
                    "tactic": mitre["tactic"]
                },
                "sample_payload": sample_payload,
                "containment_directive": mitre["directive"],
                "events": cat_events
            })

        # Sort clusters by severity (Critical first) then by count
        clusters.sort(key=lambda c: (severity_rank.get(c["severity"], 1), c["event_count"]), reverse=True)

        return jsonify({
            "status": "success",
            "session_id": session_id or "active_session",
            "total_events": len(events),
            "cluster_count": len(clusters),
            "clusters": clusters
        }), 200

    except Exception as e:
        logger.error(f"Error compiling attack clusters: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to compute attack clusters: {str(e)}"
        }), 500
