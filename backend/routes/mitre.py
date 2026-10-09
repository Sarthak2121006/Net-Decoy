"""
MITRE ATT&CK Enterprise Matrix Evaluation Route (GET /api/mitre)
Provides real-time technique mapping, heat intensity scoring, and evidence correlation.
"""
from flask import Blueprint, request, jsonify
from backend.database.db import SessionLocal
from backend.database.models import EventModel
import json
import logging

logger = logging.getLogger(__name__)
mitre_bp = Blueprint("mitre", __name__)

MITRE_MATRIX_DEFINITION = [
    {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "techniques": [
            {
                "id": "T1595.002",
                "name": "Vulnerability Scanning",
                "description": "Adversary probes web application surfaces and administrative endpoints to discover vulnerable paths.",
                "keywords": ["scan", "probe", "admin", "config", "swagger", "enum"],
                "mitigation": "Deploy dynamic honeypot tarpits and block automated route scanners at ingress WAF.",
                "sub_techniques": ["T1595.001", "T1595.002"]
            },
            {
                "id": "T1592",
                "name": "Gather Victim Host Info",
                "description": "Probing internal API schemas and documentation endpoints to fingerprint architecture.",
                "keywords": ["api", "schema", "swagger", "docs", "version"],
                "mitigation": "Restrict API documentation visibility and monitor unauthorized schema scraping.",
                "sub_techniques": ["T1592.001"]
            }
        ]
    },
    {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "techniques": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing App",
                "description": "Exploiting web input vulnerabilities (SQL injection, path traversal) to gain unauthorized access.",
                "keywords": ["sql", "inject", "traversal", "search", "database", "passwd"],
                "mitigation": "Enforce strict parameterized queries, input sanitization, and deploy deception canary tables.",
                "sub_techniques": ["T1190"]
            },
            {
                "id": "T1078.001",
                "name": "Default Accounts",
                "description": "Attempting authentication with default administrative or service credentials.",
                "keywords": ["admin", "root", "guest", "default", "test"],
                "mitigation": "Disable default accounts, enforce MFA, and trap repeated attempts in synthetic auth portals.",
                "sub_techniques": ["T1078"]
            }
        ]
    },
    {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "techniques": [
            {
                "id": "T1059",
                "name": "Command & Scripting",
                "description": "Injecting operating system commands or shell escape characters into input fields.",
                "keywords": ["cmd", "exec", "sh", "bash", "system", "whoami"],
                "mitigation": "Sandbox execution environments and alert on system command delimiters in web forms.",
                "sub_techniques": ["T1059.004"]
            }
        ]
    },
    {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "techniques": [
            {
                "id": "T1110.003",
                "name": "Password Spraying / Brute Force",
                "description": "High-frequency authentication attempts with common password dictionaries.",
                "keywords": ["failed_login", "brute", "auth", "login", "password", "spray"],
                "mitigation": "Implement progressive honeypot delay throttling and IP-based automated quarantine.",
                "sub_techniques": ["T1110.001", "T1110.003"]
            },
            {
                "id": "T1552.001",
                "name": "Credentials in Files / Honeytokens",
                "description": "Searching for exposed API keys, private keys, or `.env` credential files.",
                "keywords": ["env", "jwt", "key", "token", "secret", "bearer"],
                "mitigation": "Deploy synthetic honeytokens and monitor for active unauthorized key usage.",
                "sub_techniques": ["T1552"]
            }
        ]
    },
    {
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "techniques": [
            {
                "id": "T1083",
                "name": "File and Directory Discovery",
                "description": "Adversary navigates directory structure using path traversal (`../`) and sensitive file enumeration.",
                "keywords": ["traversal", "path", "etc", "passwd", "file", "backup", "dir"],
                "mitigation": "Chroot jail file access, validate path normalization, and feed synthetic directory trees.",
                "sub_techniques": ["T1083"]
            },
            {
                "id": "T1046",
                "name": "Network Service Scanning",
                "description": "Probing multiple decoy service ports and internal microservice routes.",
                "keywords": ["scan", "port", "route", "endpoint", "404", "recon"],
                "mitigation": "Employ decoy port listeners and record origin source IP behavior patterns.",
                "sub_techniques": ["T1046"]
            }
        ]
    },
    {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "techniques": [
            {
                "id": "T1078.004",
                "name": "Role Override & Token Forgery",
                "description": "Tampering with session authorization claims or parameters to assume administrative roles.",
                "keywords": ["privilege", "role", "admin_override", "escalat", "bypass", "super_admin"],
                "mitigation": "Enforce cryptographic JWT signature verification and trap role tampering in sandbox.",
                "sub_techniques": ["T1078.004"]
            }
        ]
    },
    {
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "techniques": [
            {
                "id": "T1567",
                "name": "Exfiltration Over Web Service",
                "description": "Adversary requests bulk download of sensitive corporate backup archives and databases.",
                "keywords": ["backup", "download", "sql.gz", "dump", "exfil", "archive", "export"],
                "mitigation": "Serve watermarked decoy archives with beaconing honeytokens and trigger instant alerts.",
                "sub_techniques": ["T1567"]
            }
        ]
    }
]

@mitre_bp.route("/api/mitre", methods=["GET"])
def get_mitre_matrix():
    """
    Evaluate MITRE ATT&CK techniques against active telemetry database events.
    """
    try:
        db = SessionLocal()
        events = []
        try:
            db_events = db.query(EventModel).order_by(EventModel.timestamp.desc()).limit(200).all()
            events = [e.to_dict() for e in db_events]
        finally:
            db.close()

        tactics_output = []
        total_active_techniques = 0
        engaged_tactics_count = 0
        highest_heat = 0
        top_technique_name = "None Active"

        for tactic in MITRE_MATRIX_DEFINITION:
            tactic_engaged = False
            techniques_list = []

            for tech in tactic["techniques"]:
                matched_events = []
                keywords = tech["keywords"]

                for ev in events:
                    act = (ev.get("action") or "").lower()
                    page = (ev.get("page") or "").lower()
                    etype = (ev.get("event_type") or "").lower()
                    payload_str = json.dumps(ev.get("payload") or {}).lower()
                    combined_text = f"{act} {page} {etype} {payload_str}"

                    # Match keyword triggers
                    if any(kw in combined_text for kw in keywords):
                        matched_events.append({
                            "event_id": ev.get("event_id"),
                            "timestamp": ev.get("timestamp"),
                            "source_ip": ev.get("source_ip"),
                            "page": ev.get("page"),
                            "action": ev.get("action"),
                            "severity": ev.get("severity", "MEDIUM"),
                            "payload": ev.get("payload", {})
                        })

                hit_count = len(matched_events)
                is_active = hit_count > 0
                if is_active:
                    total_active_techniques += 1
                    tactic_engaged = True

                # Calculate heat intensity score (0 - 100)
                heat_score = min(100, hit_count * 25)
                if heat_score > highest_heat:
                    highest_heat = heat_score
                    top_technique_name = f"{tech['id']} — {tech['name']}"

                # Severity level based on hits & events
                crit_hits = sum(1 for m in matched_events if m.get("severity") in ("CRITICAL", "HIGH"))
                if crit_hits > 0:
                    severity = "CRITICAL" if any(m.get("severity") == "CRITICAL" for m in matched_events) else "HIGH"
                elif hit_count > 0:
                    severity = "MEDIUM"
                else:
                    severity = "INACTIVE"

                techniques_list.append({
                    "id": tech["id"],
                    "name": tech["name"],
                    "description": tech["description"],
                    "mitigation": tech["mitigation"],
                    "sub_techniques": tech["sub_techniques"],
                    "is_active": is_active,
                    "hit_count": hit_count,
                    "heat_score": heat_score,
                    "severity": severity,
                    "matched_events": matched_events[:5],  # Top 5 most recent evidence samples
                    "evidence": matched_events[:5]
                })

            if tactic_engaged:
                engaged_tactics_count += 1

            tactics_output.append({
                "tactic_id": tactic["tactic_id"],
                "tactic_name": tactic["tactic_name"],
                "is_engaged": tactic_engaged,
                "techniques": techniques_list
            })

        return jsonify({
            "status": "success",
            "tactics": tactics_output,
            "metrics": {
                "total_tactics": len(MITRE_MATRIX_DEFINITION),
                "engaged_tactics": engaged_tactics_count,
                "active_techniques": total_active_techniques,
                "overall_heat_score": highest_heat,
                "top_active_technique": top_technique_name
            }
        }), 200

    except Exception as e:
        logger.error(f"Error evaluating MITRE matrix: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Failed to generate MITRE matrix"}), 500
