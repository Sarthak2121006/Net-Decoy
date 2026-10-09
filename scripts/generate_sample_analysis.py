"""
Generates shared/sample_analysis.json by running the full IEEE SYNAPSE 2026 demo scenario:
- 5 failed logins (BRUTE_FORCE)
- admin & api scan (SCANNING)
- SQL injection in database console (SQL_INJECTION)
- backup portal sensitive file access (SENSITIVE_ACCESS)
- path traversal attempt in search portal (PATH_TRAVERSAL)
"""

import json
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from intelligence import analyze_session


def generate_sample_analysis():
    repo_root = Path(__file__).resolve().parent.parent
    output_path = repo_root / "shared" / "sample_analysis.json"

    demo_events = [
        # Initial access / reconnaissance
        {
            "event_id": "evt_demo_001",
            "session_id": "sess_001",
            "timestamp": "2026-10-08T14:30:00Z",
            "source_ip": "192.168.1.105",
            "page": "login",
            "action": "page_view",
            "event_type": "navigation",
            "payload": {}
        },
        # 5 failed login attempts
        {
            "event_id": "evt_demo_002",
            "session_id": "sess_001",
            "timestamp": "2026-10-08T14:30:05Z",
            "source_ip": "192.168.1.105",
            "page": "login",
            "action": "failed_login",
            "event_type": "authentication",
            "payload": {"username": "admin"}
        },
        {
            "event_id": "evt_demo_003",
            "session_id": "sess_001",
            "timestamp": "2026-10-08T14:30:10Z",
            "source_ip": "192.168.1.105",
            "page": "login",
            "action": "failed_login",
            "event_type": "authentication",
            "payload": {"username": "admin"}
        },
        {
            "event_id": "evt_demo_004",
            "session_id": "sess_001",
            "timestamp": "2026-10-08T14:30:15Z",
            "source_ip": "192.168.1.105",
            "page": "login",
            "action": "failed_login",
            "event_type": "authentication",
            "payload": {"username": "root"}
        },
        {
            "event_id": "evt_demo_005",
            "session_id": "sess_001",
            "timestamp": "2026-10-08T14:30:20Z",
            "source_ip": "192.168.1.105",
            "page": "login",
            "action": "failed_login",
            "event_type": "authentication",
            "payload": {"username": "administrator"}
        },
        {
            "event_id": "evt_demo_006",
            "session_id": "sess_001",
            "timestamp": "2026-10-08T14:30:25Z",
            "source_ip": "192.168.1.105",
            "page": "login",
            "action": "failed_login",
            "event_type": "authentication",
            "payload": {"username": "admin"}
        },
        # Admin & API scan
        {
            "event_id": "evt_demo_007",
            "session_id": "sess_001",
            "timestamp": "2026-10-08T14:30:45Z",
            "source_ip": "192.168.1.105",
            "page": "admin",
            "action": "probe",
            "event_type": "navigation",
            "payload": {"endpoint": "/admin/dashboard"}
        },
        {
            "event_id": "evt_demo_008",
            "session_id": "sess_001",
            "timestamp": "2026-10-08T14:30:55Z",
            "source_ip": "192.168.1.105",
            "page": "api",
            "action": "api_probe",
            "event_type": "api_call",
            "payload": {"endpoint": "/api/v1/users"}
        },
        # SQL Injection
        {
            "event_id": "evt_demo_009",
            "session_id": "sess_001",
            "timestamp": "2026-10-08T14:31:00Z",
            "source_ip": "192.168.1.105",
            "page": "database",
            "action": "query_submit",
            "event_type": "database_query",
            "payload": {"query": "' OR '1'='1' UNION SELECT null, username, password FROM users--"}
        },
        # Backup Access
        {
            "event_id": "evt_demo_010",
            "session_id": "sess_001",
            "timestamp": "2026-10-08T14:31:45Z",
            "source_ip": "192.168.1.105",
            "page": "backup",
            "action": "file_download",
            "event_type": "file_access",
            "payload": {"file": "customer_data_backup.sql"}
        },
        # Path Traversal
        {
            "event_id": "evt_demo_011",
            "session_id": "sess_001",
            "timestamp": "2026-10-08T14:32:00Z",
            "source_ip": "192.168.1.105",
            "page": "search",
            "action": "search",
            "event_type": "input_submission",
            "payload": {"query": "../../etc/passwd"}
        },
    ]

    analysis = analyze_session(demo_events, session_id="sess_001")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2)

    print(f"Sample analysis generated successfully at: {output_path}")
    return analysis


if __name__ == "__main__":
    generate_sample_analysis()
