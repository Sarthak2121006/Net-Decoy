"""
NetDecoy - Demo Replay Module
Runs via: python -m intelligence.demo

Replays the IEEE SYNAPSE 2026 hackathon demo scenario step-by-step,
displaying progressive detections, risk score, level, current attack stage,
and predicted next stage with pattern confidence after each interaction.
"""

from typing import Any, Dict, List
from intelligence import analyze_session


DEMO_EVENTS: List[Dict[str, Any]] = [
    {
        "event_id": "evt_001",
        "session_id": "demo_replay_session",
        "timestamp": "2026-10-08T14:30:00Z",
        "source_ip": "192.168.1.105",
        "page": "login",
        "action": "page_view",
        "event_type": "navigation",
        "payload": {}
    },
    {
        "event_id": "evt_002",
        "session_id": "demo_replay_session",
        "timestamp": "2026-10-08T14:30:05Z",
        "source_ip": "192.168.1.105",
        "page": "login",
        "action": "failed_login",
        "event_type": "authentication",
        "payload": {"username": "admin"}
    },
    {
        "event_id": "evt_003",
        "session_id": "demo_replay_session",
        "timestamp": "2026-10-08T14:30:10Z",
        "source_ip": "192.168.1.105",
        "page": "login",
        "action": "failed_login",
        "event_type": "authentication",
        "payload": {"username": "admin"}
    },
    {
        "event_id": "evt_004",
        "session_id": "demo_replay_session",
        "timestamp": "2026-10-08T14:30:15Z",
        "source_ip": "192.168.1.105",
        "page": "login",
        "action": "failed_login",
        "event_type": "authentication",
        "payload": {"username": "root"}
    },
    {
        "event_id": "evt_005",
        "session_id": "demo_replay_session",
        "timestamp": "2026-10-08T14:30:20Z",
        "source_ip": "192.168.1.105",
        "page": "login",
        "action": "failed_login",
        "event_type": "authentication",
        "payload": {"username": "administrator"}
    },
    {
        "event_id": "evt_006",
        "session_id": "demo_replay_session",
        "timestamp": "2026-10-08T14:30:25Z",
        "source_ip": "192.168.1.105",
        "page": "login",
        "action": "failed_login",
        "event_type": "authentication",
        "payload": {"username": "admin"}
    },
    {
        "event_id": "evt_007",
        "session_id": "demo_replay_session",
        "timestamp": "2026-10-08T14:30:45Z",
        "source_ip": "192.168.1.105",
        "page": "admin",
        "action": "probe",
        "event_type": "navigation",
        "payload": {"endpoint": "/admin/dashboard"}
    },
    {
        "event_id": "evt_008",
        "session_id": "demo_replay_session",
        "timestamp": "2026-10-08T14:30:55Z",
        "source_ip": "192.168.1.105",
        "page": "api",
        "action": "api_probe",
        "event_type": "api_call",
        "payload": {"endpoint": "/api/v1/users"}
    },
    {
        "event_id": "evt_009",
        "session_id": "demo_replay_session",
        "timestamp": "2026-10-08T14:31:00Z",
        "source_ip": "192.168.1.105",
        "page": "database",
        "action": "query_submit",
        "event_type": "database_query",
        "payload": {"query": "' OR '1'='1' UNION SELECT null, username, password FROM users--"}
    },
    {
        "event_id": "evt_010",
        "session_id": "demo_replay_session",
        "timestamp": "2026-10-08T14:31:45Z",
        "source_ip": "192.168.1.105",
        "page": "backup",
        "action": "file_download",
        "event_type": "file_access",
        "payload": {"file": "customer_data_backup.sql"}
    },
    {
        "event_id": "evt_011",
        "session_id": "demo_replay_session",
        "timestamp": "2026-10-08T14:32:00Z",
        "source_ip": "192.168.1.105",
        "page": "search",
        "action": "search",
        "event_type": "input_submission",
        "payload": {"query": "../../etc/passwd"}
    },
]


def run_demo_replay():
    print("=" * 70)
    print(" NetDecoy Threat Intelligence & AI Engine - Interactive Demo Replay")
    print("=" * 70)

    total_steps = len(DEMO_EVENTS)

    for i in range(1, total_steps + 1):
        events_so_far = DEMO_EVENTS[:i]
        current_event = events_so_far[-1]
        page = current_event.get("page")
        action = current_event.get("action")

        result = analyze_session(events_so_far, session_id="demo_replay_session")

        detections = result.get("detected_attack_types", [])
        risk = result.get("risk", {})
        score = risk.get("score", 0)
        level = risk.get("level", "LOW")

        journey = result.get("journey", {})
        current_stage = journey.get("current_stage", "RECONNAISSANCE")

        prediction = result.get("prediction", {})
        next_stage = prediction.get("next_stage", "UNKNOWN")
        confidence = prediction.get("confidence", 0)
        conf_label = prediction.get("confidence_label", "Pattern confidence")

        print(f"\n[Step {i:02d}/{total_steps:02d}] Resource: /{page} | Action: {action}")
        print(f"  - Detections        : {detections if detections else 'None (nominal activity)'}")
        print(f"  - Risk Assessment   : {score}/100 [{level}]")
        print(f"  - Current Stage     : {current_stage}")
        print(f"  - Next-Stage Pred.  : {next_stage} ({confidence}% {conf_label})")

    print("\n" + "=" * 70)
    print(" Demo replay sequence completed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    run_demo_replay()
