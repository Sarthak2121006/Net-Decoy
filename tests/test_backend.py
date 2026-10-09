"""
Comprehensive Integration and Unit Tests for NetDecoy Backend
"""
import pytest
import json
import os
import tempfile
from backend.app import create_app
from backend.database.db import reset_db
from backend.services.collector import log_event
from backend.services.geo_service import get_ip_geo
from traps.collector_client import TrapCollectorClient

@pytest.fixture
def client():
    """Create a temporary test client with clean SQLite database."""
    app = create_app({"TESTING": True})
    with app.test_client() as client:
        with app.app_context():
            reset_db()
        yield client
        with app.app_context():
            reset_db()

def test_health_and_root(client):
    """Verify backend health and root discovery endpoints."""
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json["status"] == "online"

    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    assert res_health.json["status"] == "healthy"

def test_event_ingestion_and_persistence(client):
    """Test POST /api/events creates and stores events with full schema."""
    payload = {
        "session_id": "sess_test_100",
        "source_ip": "192.168.1.100",
        "page": "login",
        "action": "failed_login",
        "event_type": "authentication",
        "payload": {"username": "admin", "password": "' OR 1=1 --"}
    }
    res = client.post("/api/events", json=payload)
    assert res.status_code == 201
    data = res.json
    assert data["status"] == "success"
    event = data["event"]
    assert event["session_id"] == "sess_test_100"
    assert event["page"] == "login"
    assert event["action"] == "failed_login"
    assert event["event_type"] == "authentication"
    assert "event_id" in event
    assert "timestamp" in event
    assert "geo" in event
    assert event["payload"]["username"] == "admin"

def test_event_retrieval_and_filters(client):
    """Test GET /api/events with filters (session_id, severity, event_type)."""
    # Ingest 3 distinct events
    client.post("/api/events", json={
        "session_id": "sess_A",
        "source_ip": "10.0.0.1",
        "page": "env_leak",
        "action": "read_env",
        "event_type": "reconnaissance"
    })
    client.post("/api/events", json={
        "session_id": "sess_A",
        "source_ip": "10.0.0.1",
        "page": "admin_portal",
        "action": "sql_injection",
        "event_type": "exploitation",
        "severity": "CRITICAL"
    })
    client.post("/api/events", json={
        "session_id": "sess_B",
        "source_ip": "10.0.0.2",
        "page": "login",
        "action": "brute_force",
        "event_type": "authentication"
    })

    # Query all
    res_all = client.get("/api/events")
    assert res_all.status_code == 200
    assert res_all.json["count"] == 3

    # Filter by session_id
    res_sess = client.get("/api/events?session_id=sess_A")
    assert res_sess.status_code == 200
    assert res_sess.json["count"] == 2

    # Filter by severity
    res_sev = client.get("/api/events?severity=CRITICAL")
    assert res_sev.status_code == 200
    assert res_sev.json["count"] == 1
    assert res_sev.json["events"][0]["action"] == "sql_injection"

def test_stats_endpoint(client):
    """Verify GET /api/stats returns accurate KPI counts."""
    # Empty stats
    res0 = client.get("/api/stats")
    assert res0.json["total_events"] == 0
    assert res0.json["total_sessions"] == 0

    # Ingest some attack events
    client.post("/api/events", json={
        "session_id": "sess_1",
        "page": "login",
        "action": "failed_login",
        "event_type": "authentication"
    })
    client.post("/api/events", json={
        "session_id": "sess_1",
        "page": "admin",
        "action": "sql_injection",
        "event_type": "exploitation",
        "severity": "CRITICAL"
    })
    client.post("/api/events", json={
        "session_id": "sess_2",
        "page": "probe",
        "action": "scanning",
        "event_type": "reconnaissance"
    })

    res = client.get("/api/stats")
    assert res.status_code == 200
    stats = res.json
    assert stats["total_events"] == 3
    assert stats["total_sessions"] == 2
    assert stats["threats_detected"] >= 2
    assert stats["high_risk"] >= 1

def test_risk_endpoint(client):
    """Verify GET /api/risk returns score, level, and breakdown."""
    client.post("/api/events", json={
        "session_id": "sess_risk_test",
        "page": "login",
        "action": "sql_injection",
        "event_type": "exploitation",
        "severity": "CRITICAL"
    })
    client.post("/api/events", json={
        "session_id": "sess_risk_test",
        "page": "login",
        "action": "failed_login",
        "event_type": "authentication"
    })

    res = client.get("/api/risk?session_id=sess_risk_test")
    assert res.status_code == 200
    data = res.json
    assert "score" in data
    assert data["score"] > 0
    assert "level" in data
    assert "breakdown" in data
    assert "sql_injection" in data["breakdown"]
    assert "brute_force" in data["breakdown"]

def test_journey_endpoint(client):
    """Verify GET /api/journey orders attacker actions chronologically."""
    client.post("/api/events", json={
        "session_id": "sess_journey",
        "page": "env_leak",
        "action": "read_env",
        "event_type": "reconnaissance"
    })
    client.post("/api/events", json={
        "session_id": "sess_journey",
        "page": "login",
        "action": "failed_login",
        "event_type": "authentication"
    })
    client.post("/api/events", json={
        "session_id": "sess_journey",
        "page": "portal",
        "action": "sql_injection",
        "event_type": "exploitation"
    })

    res = client.get("/api/journey?session_id=sess_journey")
    assert res.status_code == 200
    stages = res.json["stages"]
    assert len(stages) == 3
    assert stages[0]["stage"] == "Reconnaissance"
    assert stages[1]["stage"] == "Initial Access"
    assert stages[2]["stage"] == "Exploitation"

def test_analysis_and_prediction(client):
    """Verify GET /api/analysis and GET /api/prediction endpoints."""
    client.post("/api/events", json={
        "session_id": "sess_ai",
        "page": "db_admin",
        "action": "sql_injection",
        "event_type": "exploitation"
    })

    res_analysis = client.get("/api/analysis?session_id=sess_ai")
    assert res_analysis.status_code == 200
    assert res_analysis.json["status"] == "success"
    assert "threat_actor_profile" in res_analysis.json
    assert "recommendations" in res_analysis.json

    res_pred = client.get("/api/prediction?session_id=sess_ai")
    assert res_pred.status_code == 200
    assert "next_stage" in res_pred.json
    assert "confidence" in res_pred.json
    assert "basis" in res_pred.json

def test_geo_endpoint_and_fallback(client):
    """Verify GET /api/geo works and handles IP lookups gracefully."""
    res = client.get("/api/geo?ip=127.0.0.1")
    assert res.status_code == 200
    assert res.json["available"] is True

    # Unknown or invalid IP string should never crash
    res_bad = client.get("/api/geo?ip=999.999.999.999")
    assert res_bad.status_code == 200
    assert "available" in res_bad.json

def test_reset_endpoint(client):
    """Verify POST /api/reset purges state for demo repeat."""
    client.post("/api/events", json={"session_id": "s1", "page": "p1", "action": "a1", "event_type": "recon"})
    client.post("/api/events", json={"session_id": "s2", "page": "p2", "action": "a2", "event_type": "recon"})

    # Check stats non-zero
    assert client.get("/api/stats").json["total_events"] == 2

    # Reset
    res_reset = client.post("/api/reset")
    assert res_reset.status_code == 200
    assert res_reset.json["status"] == "success"

    # Confirm stats are 0
    assert client.get("/api/stats").json["total_events"] == 0
    assert client.get("/api/stats").json["total_sessions"] == 0

def test_trap_sdk_client(client):
    """Verify TrapCollectorClient communicates cleanly."""
    sdk = TrapCollectorClient(trap_name="ssh_trap")
    res = sdk.emit_event(
        session_id="sess_sdk_test",
        source_ip="192.168.1.10",
        action="brute_force",
        event_type="authentication",
        payload={"port": 2222}
    )
    assert res["status"] == "success"
    assert res["event"]["page"] == "ssh_trap"

def test_metrics_endpoint(client):
    """Verify GET /api/metrics computes breakdowns for charts."""
    client.post("/api/events", json={"session_id": "s1", "page": "login", "action": "failed_login", "event_type": "authentication", "severity": "MEDIUM"})
    client.post("/api/events", json={"session_id": "s2", "page": "db_console", "action": "sql_injection", "event_type": "exploitation", "severity": "CRITICAL"})

    res = client.get("/api/metrics")
    assert res.status_code == 200
    metrics = res.json["metrics"]
    assert "top_traps" in metrics
    assert "top_ips" in metrics
    assert "severity_distribution" in metrics
    assert "event_type_distribution" in metrics
    assert metrics["severity_distribution"]["CRITICAL"] >= 1

def test_alerts_endpoint(client):
    """Verify GET /api/alerts returns high-severity SOC alerts."""
    client.post("/api/events", json={"session_id": "sess_alert", "page": "db_console", "action": "sql_injection", "event_type": "exploitation", "severity": "CRITICAL"})
    res = client.get("/api/alerts")
    assert res.status_code == 200
    data = res.json
    assert data["status"] == "success"
    assert data["count"] >= 1
    assert data["alerts"][0]["severity"] == "CRITICAL"

def test_sessions_endpoints(client):
    """Verify GET /api/sessions and GET /api/sessions/<id>."""
    client.post("/api/events", json={"session_id": "sess_audit_99", "page": "login", "action": "failed_login", "event_type": "authentication"})
    
    # List sessions
    res_list = client.get("/api/sessions")
    assert res_list.status_code == 200
    assert res_list.json["count"] >= 1
    
    # Session detail
    res_det = client.get("/api/sessions/sess_audit_99")
    assert res_det.status_code == 200
    sess = res_det.json["session"]
    assert sess["session_id"] == "sess_audit_99"
    assert "journey" in sess
    assert "risk" in sess
    assert "prediction" in sess
    assert "analysis" in sess

def test_quarantine_endpoints(client):
    """Verify POST, GET, DELETE /api/quarantine active defense workflows."""
    # Add IP to quarantine
    res_post = client.post("/api/quarantine", json={"ip": "198.51.100.99", "reason": "Repeated SQLi"})
    assert res_post.status_code == 201
    assert res_post.json["status"] == "success"

    # List quarantines
    res_list = client.get("/api/quarantine")
    assert res_list.status_code == 200
    assert res_list.json["count"] >= 1
    assert res_list.json["quarantined_ips"][0]["ip_address"] == "198.51.100.99"

    # Delete / unquarantine IP
    res_del = client.delete("/api/quarantine/198.51.100.99")
    assert res_del.status_code == 200
    assert res_del.json["status"] == "success"

    # Confirm unquarantined
    res_list_after = client.get("/api/quarantine")
    assert res_list_after.json["count"] == 0

def test_frontend_and_traps_serving(client):
    """Verify backend successfully serves SOC Dashboard and Deception Trap HTML pages."""
    # Test Dashboard serving
    res_dash = client.get("/dashboard")
    assert res_dash.status_code == 200
    assert b"NetDecoy" in res_dash.data

    res_css = client.get("/dashboard.css")
    assert res_css.status_code == 200

    res_js = client.get("/dashboard.js")
    assert res_js.status_code == 200

    # Test Traps serving
    res_traps = client.get("/traps")
    assert res_traps.status_code == 200
    assert b"Apex Global" in res_traps.data

    res_login = client.get("/login")
    assert res_login.status_code == 200

    res_admin = client.get("/admin")
    assert res_admin.status_code == 200

    res_demo = client.get("/demo")
    assert res_demo.status_code == 200

