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

    # Test Attacker Red-Team Console (System 3)
    res_attacker = client.get("/attacker")
    assert res_attacker.status_code == 200
    assert b"Attacker Red-Team" in res_attacker.data

    res_redteam = client.get("/redteam")
    assert res_redteam.status_code == 200

    # Test Company Portal Aliases (System 2)
    res_company = client.get("/company")
    assert res_company.status_code == 200
    assert b"Apex Global" in res_company.data


def test_report_endpoint(client):
    """Verify GET /api/report returns a complete executive forensic incident dossier."""
    # Seed events across diverse attack vectors
    client.post("/api/events", json={
        "session_id": "sess_report_99",
        "page": "login",
        "action": "sql_injection",
        "event_type": "exploitation",
        "severity": "CRITICAL",
        "source_ip": "185.220.101.45",
        "payload": {"input": "admin' OR 1=1--", "vector": "SQLi"}
    })
    client.post("/api/events", json={
        "session_id": "sess_report_99",
        "page": "admin",
        "action": "failed_login",
        "event_type": "authentication",
        "severity": "HIGH",
        "source_ip": "185.220.101.45",
        "payload": {"username": "root", "attempt": 3}
    })

    # Query report for specific session
    res = client.get("/api/report?session_id=sess_report_99")
    assert res.status_code == 200
    report = res.json
    assert report["status"] == "success"
    assert report["session_id"] == "sess_report_99"
    assert "incident_reference_id" in report
    assert report["incident_reference_id"].startswith("INC-")
    assert "report_timestamp" in report
    assert "risk_assessment" in report
    assert "score" in report["risk_assessment"]
    assert "severity_level" in report["risk_assessment"]
    assert "mitre_attack_framework" in report
    assert len(report["mitre_attack_framework"]) > 0
    assert "forensic_timeline" in report
    assert len(report["forensic_timeline"]) >= 2
    assert "raw_payload_evidence" in report
    assert len(report["raw_payload_evidence"]) >= 1
    assert "ai_threat_synthesis" in report
    assert "containment_directives" in report["ai_threat_synthesis"]

    # Query general report (all sessions)
    res_gen = client.get("/api/report")
    assert res_gen.status_code == 200
    assert res_gen.json["status"] == "success"


def test_clusters_endpoint(client):
    """Verify GET /api/clusters groups concurrent events into attack campaigns."""
    # Seed multiple events of the same attack type and different attack types
    client.post("/api/events", json={"session_id": "sess_cluster", "page": "database", "action": "sql_injection", "event_type": "sqli", "severity": "CRITICAL", "payload": {"query": "' OR 1=1"}})
    client.post("/api/events", json={"session_id": "sess_cluster", "page": "database", "action": "sql_union", "event_type": "sqli", "severity": "CRITICAL", "payload": {"query": "UNION SELECT"}})
    client.post("/api/events", json={"session_id": "sess_cluster", "page": "login", "action": "failed_login", "event_type": "authentication", "severity": "HIGH", "payload": {"user": "admin"}})
    client.post("/api/events", json={"session_id": "sess_cluster", "page": "login", "action": "failed_login", "event_type": "authentication", "severity": "HIGH", "payload": {"user": "root"}})

    res = client.get("/api/clusters?session_id=sess_cluster")
    assert res.status_code == 200
    data = res.json
    assert data["status"] == "success"
    assert data["total_events"] >= 4
    assert data["cluster_count"] >= 2

    # Verify cluster structure
    cluster_types = [c["attack_type"] for c in data["clusters"]]
    assert "sql_injection" in cluster_types
    assert "brute_force" in cluster_types

    sqli_cluster = next(c for c in data["clusters"] if c["attack_type"] == "sql_injection")
    assert sqli_cluster["event_count"] >= 2
    assert sqli_cluster["severity"] == "CRITICAL"
    assert "/database" in sqli_cluster["target_endpoints"]
    assert "mitre_technique" in sqli_cluster
    assert "containment_directive" in sqli_cluster


def test_mitre_endpoint(client):
    """Verify GET /api/mitre parses events into ATT&CK matrix tactics and techniques."""
    # Ingest events across tactics
    client.post("/api/events", json={
        "session_id": "sess_mitre",
        "page": "env_leak",
        "action": "env_read",
        "event_type": "reconnaissance",
        "severity": "MEDIUM",
        "payload": {"target": ".env"}
    })
    client.post("/api/events", json={
        "session_id": "sess_mitre",
        "page": "database",
        "action": "sql_injection",
        "event_type": "sqli",
        "severity": "CRITICAL",
        "payload": {"query": "' OR 1=1"}
    })

    res = client.get("/api/mitre?session_id=sess_mitre")
    assert res.status_code == 200
    data = res.json
    assert data["status"] == "success"
    assert "metrics" in data
    assert "tactics" in data
    assert data["metrics"]["engaged_tactics"] >= 2
    assert data["metrics"]["active_techniques"] >= 2
    assert len(data["tactics"]) == 7

    # Check tactics array
    tactic_ids = [t["tactic_id"] for t in data["tactics"]]
    assert "TA0043" in tactic_ids
    assert "TA0001" in tactic_ids
    assert "TA0002" in tactic_ids
    assert "TA0006" in tactic_ids

    # Find Initial Access tactic and check SQL injection technique
    initial_access = next(t for t in data["tactics"] if t["tactic_id"] == "TA0001")
    t1190 = next(tech for tech in initial_access["techniques"] if tech["id"] == "T1190")
    assert t1190["hit_count"] >= 1
    assert t1190["heat_score"] > 0
    assert len(t1190["evidence"]) >= 1



