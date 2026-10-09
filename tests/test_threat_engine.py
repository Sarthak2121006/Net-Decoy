"""
Tests for NetDecoy Threat Detection Engine
"""

import unittest
from intelligence.threat_engine import (
    ThreatEngine,
    BruteForceDetector,
    ScanningDetector,
    SQLInjectionDetector,
    PathTraversalDetector,
    SensitiveAccessDetector,
)


class TestThreatEngine(unittest.TestCase):

    def setUp(self):
        self.threat_engine = ThreatEngine()

    def test_brute_force_detection(self):
        detector = BruteForceDetector(failure_threshold=3)
        events = [
            {"action": "failed_login", "page": "login", "payload": {"username": "admin"}},
            {"action": "failed_login", "page": "login", "payload": {"username": "admin"}},
            {"action": "failed_login", "page": "login", "payload": {"username": "root"}},
        ]
        detection = detector.evaluate_session(events)
        self.assertIsNotNone(detection)
        self.assertEqual(detection.attack_type, "BRUTE_FORCE")
        self.assertTrue(detection.detected)
        self.assertIn("3 failed login attempts", detection.evidence[0])

    def test_brute_force_below_threshold(self):
        detector = BruteForceDetector(failure_threshold=4)
        events = [
            {"action": "failed_login", "page": "login", "payload": {"username": "admin"}},
            {"action": "failed_login", "page": "login", "payload": {"username": "admin"}},
        ]
        detection = detector.evaluate_session(events)
        self.assertIsNone(detection)

    def test_scanning_detection(self):
        detector = ScanningDetector(distinct_endpoint_threshold=3)
        events = [
            {"page": "login", "action": "page_view"},
            {"page": "admin", "action": "probe"},
            {"page": "api", "action": "probe"},
            {"page": "database", "action": "page_view"},
        ]
        detection = detector.evaluate_session(events)
        self.assertIsNotNone(detection)
        self.assertEqual(detection.attack_type, "SCANNING")
        self.assertTrue(detection.detected)
        self.assertIn("Probed 4 distinct decoy resource pages", detection.evidence[0])

    def test_sql_injection_detection(self):
        detector = SQLInjectionDetector()
        
        # Test auth bypass pattern
        ev1 = {"payload": {"query": "' OR '1'='1"}}
        det1 = detector.evaluate_event(ev1)
        self.assertIsNotNone(det1)
        self.assertEqual(det1.attack_type, "SQL_INJECTION")
        self.assertEqual(det1.severity, "HIGH")

        # Test union select pattern
        ev2 = {"payload": {"query": "SELECT * FROM users UNION SELECT null, username, password FROM admin"}}
        det2 = detector.evaluate_event(ev2)
        self.assertIsNotNone(det2)
        self.assertEqual(det2.attack_type, "SQL_INJECTION")

        # Test comment pattern
        ev3 = {"payload": {"username": "admin'--"}}
        det3 = detector.evaluate_event(ev3)
        self.assertIsNotNone(det3)
        self.assertEqual(det3.attack_type, "SQL_INJECTION")

        # Harmless query should not trigger
        ev4 = {"payload": {"query": "SELECT status FROM server_health"}}
        det4 = detector.evaluate_event(ev4)
        self.assertIsNone(det4)

    def test_path_traversal_detection(self):
        detector = PathTraversalDetector()

        # Step up traversal
        ev1 = {"payload": {"file": "../../etc/passwd"}}
        det1 = detector.evaluate_event(ev1)
        self.assertIsNotNone(det1)
        self.assertEqual(det1.attack_type, "PATH_TRAVERSAL")

        # Encoded traversal
        ev2 = {"payload": {"path": "%2e%2e%2f%2e%2e%2fsecret.txt"}}
        det2 = detector.evaluate_event(ev2)
        self.assertIsNotNone(det2)
        self.assertEqual(det2.attack_type, "PATH_TRAVERSAL")

        # Safe input
        ev3 = {"payload": {"file": "document.pdf"}}
        det3 = detector.evaluate_event(ev3)
        self.assertIsNone(det3)

    def test_sensitive_access_detection(self):
        detector = SensitiveAccessDetector()

        # Direct access to backup page with download
        ev1 = {"page": "backup", "action": "file_download", "payload": {"file": "customer_dump.sql.gz"}}
        det1 = detector.evaluate_event(ev1)
        self.assertIsNotNone(det1)
        self.assertEqual(det1.attack_type, "SENSITIVE_ACCESS")

        # Harmless access to non-sensitive asset
        ev2 = {"page": "login", "action": "page_view", "payload": {}}
        det2 = detector.evaluate_event(ev2)
        self.assertIsNone(det2)

    def test_master_threat_engine_session(self):
        events = [
            {"event_id": "e1", "page": "login", "action": "failed_login", "payload": {"username": "admin"}},
            {"event_id": "e2", "page": "login", "action": "failed_login", "payload": {"username": "admin"}},
            {"event_id": "e3", "page": "login", "action": "failed_login", "payload": {"username": "admin"}},
            {"event_id": "e4", "page": "admin", "action": "probe"},
            {"event_id": "e5", "page": "database", "action": "query_submit", "payload": {"query": "' OR 1=1--"}},
            {"event_id": "e6", "page": "backup", "action": "file_download", "payload": {"file": "database.bak"}},
            {"event_id": "e7", "page": "search", "action": "search", "payload": {"path": "../../etc/hosts"}},
        ]
        detections = self.threat_engine.evaluate_session(events)
        detected_types = {d.attack_type for d in detections}
        self.assertIn("BRUTE_FORCE", detected_types)
        self.assertIn("SQL_INJECTION", detected_types)
        self.assertIn("PATH_TRAVERSAL", detected_types)
        self.assertIn("SENSITIVE_ACCESS", detected_types)
        self.assertIn("REPEATED_SUSPICIOUS", detected_types)


if __name__ == "__main__":
    unittest.main()
