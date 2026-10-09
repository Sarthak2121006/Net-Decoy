"""
Tests for NetDecoy Attacker Journey Engine
"""

import unittest
from intelligence.journey_engine import JourneyEngine
from intelligence.threat_engine import AttackDetection


class TestJourneyEngine(unittest.TestCase):

    def setUp(self):
        self.journey_engine = JourneyEngine()

    def test_stage_mapping(self):
        # Brute force login -> CREDENTIAL_ACCESS
        ev1 = {"event_id": "e1", "page": "login", "action": "failed_login"}
        det1 = [AttackDetection("BRUTE_FORCE", True, "HIGH", ["failed"], event_id="e1")]
        stage1 = self.journey_engine.map_event_to_stage(ev1, det1)
        self.assertEqual(stage1, "CREDENTIAL_ACCESS")

        # SQL Injection -> PRIVILEGE_ESCALATION
        ev2 = {"event_id": "e2", "page": "database", "action": "query_submit"}
        det2 = [AttackDetection("SQL_INJECTION", True, "HIGH", ["union"], event_id="e2")]
        stage2 = self.journey_engine.map_event_to_stage(ev2, det2)
        self.assertEqual(stage2, "PRIVILEGE_ESCALATION")

        # Backup access -> DATA_ACCESS
        ev3 = {"event_id": "e3", "page": "backup", "action": "file_download"}
        det3 = [AttackDetection("SENSITIVE_ACCESS", True, "HIGH", ["backup"], event_id="e3")]
        stage3 = self.journey_engine.map_event_to_stage(ev3, det3)
        self.assertEqual(stage3, "DATA_ACCESS")

    def test_build_journey_timeline(self):
        events = [
            {"event_id": "e1", "page": "login", "action": "page_view", "timestamp": "2026-10-09T10:00:00Z"},
            {"event_id": "e2", "page": "admin", "action": "probe", "timestamp": "2026-10-09T10:01:00Z"},
            {"event_id": "e3", "page": "database", "action": "query_submit", "timestamp": "2026-10-09T10:02:00Z"},
            {"event_id": "e4", "page": "backup", "action": "file_download", "timestamp": "2026-10-09T10:03:00Z"},
        ]
        detections = [
            AttackDetection("SCANNING", True, "MEDIUM", ["admin probe"], event_id="e2"),
            AttackDetection("SQL_INJECTION", True, "HIGH", ["or 1=1"], event_id="e3"),
            AttackDetection("SENSITIVE_ACCESS", True, "HIGH", ["backup download"], event_id="e4"),
        ]

        journey = self.journey_engine.build_journey(events, detections, session_id="test_sess")
        self.assertEqual(journey["total_steps"], 4)
        self.assertEqual(journey["current_stage"], "DATA_ACCESS")
        self.assertIn("RECONNAISSANCE", journey["stages_visited"])
        self.assertIn("PRIVILEGE_ESCALATION", journey["stages_visited"])
        self.assertIn("DATA_ACCESS", journey["stages_visited"])
        self.assertEqual(journey["timeline"][2]["stage"], "PRIVILEGE_ESCALATION")
        self.assertEqual(journey["timeline"][2]["detection"], "SQL_INJECTION")


if __name__ == "__main__":
    unittest.main()
