"""
NetDecoy Attack Simulator
Simulates realistic multi-stage adversary journeys across honeypot traps for live hackathon demos.
"""
import time
import requests
import json
import random
import sys
import os

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BACKEND_URL = "http://localhost:5000"

ATTACK_SCENARIOS = [
    {
        "name": "Scenario 1: Automated Credential Stuffing & SQL Injection",
        "session_id": "sess_demo_alpha",
        "source_ip": "198.51.100.42",
        "steps": [
            {
                "page": "env_leak",
                "action": "probe_endpoint",
                "event_type": "reconnaissance",
                "severity": "LOW",
                "payload": {"uri": "/.env", "method": "GET", "user_agent": "Nmap NSE Engine"},
                "delay": 0.5
            },
            {
                "page": "api_explorer",
                "action": "swagger_scrape",
                "event_type": "reconnaissance",
                "severity": "LOW",
                "payload": {"endpoint": "/api/v1/internal/users", "method": "OPTIONS"},
                "delay": 0.5
            },
            {
                "page": "login",
                "action": "failed_login",
                "event_type": "authentication",
                "severity": "MEDIUM",
                "payload": {"username": "admin", "password": "password123"},
                "delay": 0.5
            },
            {
                "page": "login",
                "action": "failed_login",
                "event_type": "authentication",
                "severity": "MEDIUM",
                "payload": {"username": "root", "password": "toor"},
                "delay": 0.5
            },
            {
                "page": "login",
                "action": "sql_injection",
                "event_type": "exploitation",
                "severity": "CRITICAL",
                "payload": {"username": "admin' OR '1'='1' --", "password": "x"},
                "delay": 0.8
            },
            {
                "page": "db_console",
                "action": "data_exfiltration",
                "event_type": "data_exfiltration",
                "severity": "CRITICAL",
                "payload": {"query": "SELECT table_name, column_name FROM information_schema.columns;"},
                "delay": 0.8
            }
        ]
    },
    {
        "name": "Scenario 2: Directory Traversal & Configuration Theft",
        "session_id": "sess_demo_bravo",
        "source_ip": "203.0.113.88",
        "steps": [
            {
                "page": "file_portal",
                "action": "scan_files",
                "event_type": "reconnaissance",
                "severity": "LOW",
                "payload": {"path": "/public/documents"},
                "delay": 0.5
            },
            {
                "page": "file_portal",
                "action": "directory_traversal",
                "event_type": "reconnaissance",
                "severity": "HIGH",
                "payload": {"file_param": "../../../../etc/passwd"},
                "delay": 0.5
            },
            {
                "page": "backup_portal",
                "action": "privilege_escalation",
                "event_type": "privilege_escalation",
                "severity": "CRITICAL",
                "payload": {"token_forge": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ"},
                "delay": 0.8
            }
        ]
    }
]

def run_simulation(backend_url: str = BACKEND_URL, reset_first: bool = True):
    print("=" * 60)
    print("[INFO] Starting NetDecoy Attack Simulation Suite")
    print(f"[INFO] Target Backend: {backend_url}")
    print("=" * 60)

    try:
        res = requests.get(f"{backend_url}/api/health", timeout=3.0)
        if res.status_code != 200:
            print("[ERROR] Backend is not reachable or healthy. Start backend first with: python backend/app.py")
            return False
        print("[OK] Backend connection verified.")
    except Exception as e:
        print(f"[ERROR] Connection error: {e}")
        print("[HINT] Ensure 'python backend/app.py' is running.")
        return False

    if reset_first:
        print("\n[INFO] Resetting demo database to clean state...")
        requests.post(f"{backend_url}/api/reset")
        print("[OK] Database reset.")

    for scenario in ATTACK_SCENARIOS:
        print(f"\n[EXEC] Executing {scenario['name']}")
        print(f"Session: {scenario['session_id']} | Origin IP: {scenario['source_ip']}")
        print("-" * 50)

        for i, step in enumerate(scenario["steps"], start=1):
            time.sleep(step["delay"])
            payload_data = {
                "session_id": scenario["session_id"],
                "source_ip": scenario["source_ip"],
                "page": step["page"],
                "action": step["action"],
                "event_type": step["event_type"],
                "severity": step["severity"],
                "payload": step["payload"]
            }

            try:
                post_res = requests.post(f"{backend_url}/api/events", json=payload_data, timeout=3.0)
                if post_res.status_code == 201:
                    evt = post_res.json()["event"]
                    print(f"  [{i}/{len(scenario['steps'])}] Event -> Page: {evt['page']} | Action: {evt['action']} | Severity: {evt['severity']}")
                else:
                    print(f"  [WARN] Event failed with status: {post_res.status_code}")
            except Exception as err:
                print(f"  [ERROR] Error emitting event: {err}")

    print("\n" + "=" * 60)
    print("POST-SIMULATION DASHBOARD TELEMETRY")
    print("=" * 60)

    stats = requests.get(f"{backend_url}/api/stats").json()
    print(f"Total Events: {stats.get('total_events')} | Total Sessions: {stats.get('total_sessions')}")
    print(f"Threats Detected: {stats.get('threats_detected')} | High Risk: {stats.get('high_risk')}")

    risk = requests.get(f"{backend_url}/api/risk").json()
    print(f"Overall Risk Score: {risk.get('score')}/100 [{risk.get('level')}]")
    print(f"Threat Breakdown: {json.dumps(risk.get('breakdown', {}), indent=2)}")

    pred = requests.get(f"{backend_url}/api/prediction").json()
    print(f"Predicted Next Attack Stage: {pred.get('next_stage')} (Confidence: {pred.get('confidence')}%)")
    print(f"Basis: {pred.get('basis')}")

    analysis = requests.get(f"{backend_url}/api/analysis").json()
    print(f"AI Threat Profile: {analysis.get('threat_actor_profile')}")
    print(f"Summary Analysis: {analysis.get('analysis')}")

    print("\n[OK] Simulation Complete. Dashboard reflects live adversary state.")
    return True

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else BACKEND_URL
    run_simulation(url)
