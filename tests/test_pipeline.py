"""
End-to-End Tests for NetDecoy Intelligence Pipeline
Simulates the full IEEE SYNAPSE 2026 hackathon demo attack sequence.
"""

import unittest
from intelligence.pipeline import IntelligencePipeline


class TestIntelligencePipeline(unittest.TestCase):

    def setUp(self):
        self.pipeline = IntelligencePipeline()

    def test_full_hackathon_demo_pipeline(self):
        # Realistic full attack scenario matching README demo sequence
        demo_events = [
            # 1. Reconnaissance / Scanning
            {
                "event_id": "evt_001",
                "session_id": "synapse_demo_01",
                "timestamp": "2026-10-09T10:00:00Z",
                "source_ip": "192.168.1.100",
                "page": "login",
                "action": "page_view",
                "event_type": "navigation",
                "payload": {}
            },
            # 2. Brute Force (5 failed attempts)
            {
                "event_id": "evt_002",
                "session_id": "synapse_demo_01",
                "timestamp": "2026-10-09T10:00:10Z",
                "source_ip": "192.168.1.100",
                "page": "login",
                "action": "failed_login",
                "event_type": "authentication",
                "payload": {"username": "admin"}
            },
            {
                "event_id": "evt_003",
                "session_id": "synapse_demo_01",
                "timestamp": "2026-10-09T10:00:15Z",
                "source_ip": "192.168.1.100",
                "page": "login",
                "action": "failed_login",
                "event_type": "authentication",
                "payload": {"username": "admin"}
            },
            {
                "event_id": "evt_004",
                "session_id": "synapse_demo_01",
                "timestamp": "2026-10-09T10:00:20Z",
                "source_ip": "192.168.1.100",
                "page": "login",
                "action": "failed_login",
                "event_type": "authentication",
                "payload": {"username": "root"}
            },
            {
                "event_id": "evt_005",
                "session_id": "synapse_demo_01",
                "timestamp": "2026-10-09T10:00:25Z",
                "source_ip": "192.168.1.100",
                "page": "login",
                "action": "failed_login",
                "event_type": "authentication",
                "payload": {"username": "administrator"}
            },
            {
                "event_id": "evt_006",
                "session_id": "synapse_demo_01",
                "timestamp": "2026-10-09T10:00:30Z",
                "source_ip": "192.168.1.100",
                "page": "login",
                "action": "failed_login",
                "event_type": "authentication",
                "payload": {"username": "admin"}
            },
            # 3. Resource Scanning (probing admin and api)
            {
                "event_id": "evt_007",
                "session_id": "synapse_demo_01",
                "timestamp": "2026-10-09T10:01:00Z",
                "source_ip": "192.168.1.100",
                "page": "admin",
                "action": "probe",
                "event_type": "navigation",
                "payload": {"endpoint": "/admin/dashboard"}
            },
            {
                "event_id": "evt_008",
                "session_id": "synapse_demo_01",
                "timestamp": "2026-10-09T10:01:15Z",
                "source_ip": "192.168.1.100",
                "page": "api",
                "action": "api_probe",
                "event_type": "api_call",
                "payload": {"endpoint": "/api/v1/users"}
            },
            # 4. SQL Injection in Database Decoy
            {
                "event_id": "evt_009",
                "session_id": "synapse_demo_01",
                "timestamp": "2026-10-09T10:02:00Z",
                "source_ip": "192.168.1.100",
                "page": "database",
                "action": "query_submit",
                "event_type": "database_query",
                "payload": {"query": "' OR '1'='1' UNION SELECT null, username, password FROM users--"}
            },
            # 5. Sensitive Resource Access in Backup Decoy
            {
                "event_id": "evt_010",
                "session_id": "synapse_demo_01",
                "timestamp": "2026-10-09T10:03:00Z",
                "source_ip": "192.168.1.100",
                "page": "backup",
                "action": "file_download",
                "event_type": "file_access",
                "payload": {"file": "customer_database_backup.sql.gz"}
            },
            # 6. Path Traversal in Search Decoy
            {
                "event_id": "evt_011",
                "session_id": "synapse_demo_01",
                "timestamp": "2026-10-09T10:04:00Z",
                "source_ip": "192.168.1.100",
                "page": "search",
                "action": "search",
                "event_type": "input_submission",
                "payload": {"query": "../../etc/passwd"}
            },
        ]

        # Execute Pipeline
        result = self.pipeline.process_session("synapse_demo_01", demo_events)

        # 1. Verify general properties
        self.assertEqual(result["session_id"], "synapse_demo_01")
        self.assertEqual(result["event_count"], 11)

        # 2. Verify Detections
        detected_types = set(result["detected_attack_types"])
        self.assertIn("BRUTE_FORCE", detected_types)
        self.assertIn("SCANNING", detected_types)
        self.assertIn("SQL_INJECTION", detected_types)
        self.assertIn("SENSITIVE_ACCESS", detected_types)
        self.assertIn("PATH_TRAVERSAL", detected_types)
        self.assertIn("REPEATED_SUSPICIOUS", detected_types)

        # 3. Verify Risk Score
        risk = result["risk"]
        self.assertGreaterEqual(risk["score"], 80)
        self.assertLessEqual(risk["score"], 100)
        self.assertEqual(risk["level"], "CRITICAL")
        self.assertIn("brute_force", risk["breakdown"])
        self.assertIn("sql_injection", risk["breakdown"])

        # 4. Verify Journey
        journey = result["journey"]
        self.assertEqual(journey["total_steps"], 11)
        self.assertIn("CREDENTIAL_ACCESS", journey["stages_visited"])
        self.assertIn("PRIVILEGE_ESCALATION", journey["stages_visited"])
        self.assertIn("DATA_ACCESS", journey["stages_visited"])

        # 5. Verify Prediction
        prediction = result["prediction"]
        self.assertIn("next_stage", prediction)
        self.assertGreater(prediction["confidence"], 0)
        self.assertEqual(prediction["confidence_label"], "Pattern confidence")
        self.assertIn("basis", prediction)

        # 6. Verify AI Analysis (fallback)
        ai_analysis = result["ai_analysis"]
        self.assertIn("summary", ai_analysis)
        self.assertIn("likely_intent", ai_analysis)
        self.assertTrue(len(ai_analysis["evidence"]) >= 4)
        self.assertTrue(len(ai_analysis["recommended_actions"]) >= 2)


if __name__ == "__main__":
    unittest.main()
