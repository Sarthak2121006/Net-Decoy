"""
NetDecoy Backend CLI Manager
Commands to manage database, inspect telemetry, seed mock data, and check status.
"""
import sys
import os
import json

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database.db import init_db, reset_db, SessionLocal
from backend.database.models import EventModel, SessionModel
from backend.services.collector import log_event
from backend.services.intelligence_bridge import calculate_risk, get_ai_analysis, predict_next_stage

def show_help():
    print("""
NetDecoy Backend Management CLI

Usage:
  python backend/manage.py <command>

Commands:
  init       Initialize database schema
  reset      Reset database tables and state
  seed       Inject mock synthetic attack data
  status     Display current event count, sessions, and risk
  events     List recent 10 events in database
    """)

def cmd_init():
    init_db()
    print("[OK] Database schema initialized successfully.")

def cmd_reset():
    reset_db()
    print("[OK] Database reset to clean state.")

def cmd_seed():
    print("[INFO] Seeding synthetic attack telemetry...")
    mock_events = [
        {"session_id": "sess_seed_1", "source_ip": "185.220.101.5", "page": "env_leak", "action": "scrape_env", "event_type": "reconnaissance", "severity": "LOW"},
        {"session_id": "sess_seed_1", "source_ip": "185.220.101.5", "page": "login", "action": "failed_login", "event_type": "authentication", "severity": "MEDIUM"},
        {"session_id": "sess_seed_1", "source_ip": "185.220.101.5", "page": "login", "action": "sql_injection", "event_type": "exploitation", "severity": "CRITICAL"},
        {"session_id": "sess_seed_2", "source_ip": "194.26.29.112", "page": "backup_portal", "action": "directory_traversal", "event_type": "reconnaissance", "severity": "HIGH"},
        {"session_id": "sess_seed_2", "source_ip": "194.26.29.112", "page": "db_console", "action": "privilege_escalation", "event_type": "privilege_escalation", "severity": "CRITICAL"}
    ]
    for ev in mock_events:
        log_event(**ev)
    print(f"[OK] Seeded {len(mock_events)} attack events.")

def cmd_status():
    db = SessionLocal()
    try:
        ev_count = db.query(EventModel).count()
        sess_count = db.query(SessionModel).count()
        print(f"[STATUS] Events Stored: {ev_count}")
        print(f"[STATUS] Sessions Active: {sess_count}")
        risk = calculate_risk()
        print(f"[STATUS] Risk Score: {risk['score']}/100 [{risk['level']}]")
        pred = predict_next_stage()
        print(f"[STATUS] Next Attack Stage: {pred['next_stage']} ({pred['confidence']}%)")
    finally:
        db.close()

def cmd_events():
    db = SessionLocal()
    try:
        events = db.query(EventModel).order_by(EventModel.timestamp.desc()).limit(10).all()
        print(f"--- Recent {len(events)} Events ---")
        for e in events:
            print(f"[{e.timestamp}] {e.session_id} | {e.page} -> {e.action} [{e.severity}]")
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        show_help()
        sys.exit(0)

    cmd = sys.argv[1].lower()
    if cmd == "init":
        cmd_init()
    elif cmd == "reset":
        cmd_reset()
    elif cmd == "seed":
        cmd_seed()
    elif cmd == "status":
        cmd_status()
    elif cmd == "events":
        cmd_events()
    else:
        print(f"[ERROR] Unknown command: {cmd}")
        show_help()
