"""
Tests for NetDecoy Threat Detection Engine
Includes negative tests, obfuscation tests, windowing/deduplication, and rule attribution tests.
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
        # Verify rule attribution in evidence
        self.assertIn("RULE_BRUTE_FORCE_01", detection.evidence[0])
        self.assertIn("threshold", detection.evidence[0])
        self.assertIn("matched pattern", detection.evidence[0])

    def test_brute_force_below_threshold(self):
        detector = BruteForceDetector(failure_threshold=4)
        events = [
            {"action": "failed_login", "page": "login", "payload": {"username": "admin"}},
            {"action": "failed_login", "page": "login", "payload": {"username": "admin"}},
        ]
        detection = detector.evaluate_session(events)
        self.assertIsNone(detection)

    def test_brute_force_sliding_time_window_and_per_ip(self):
        detector = BruteForceDetector(failure_threshold=3, window_seconds=60)

        # 1. Attempts spread over wide time (>60s) -> should NOT trigger
        events_spread = [
            {"action": "failed_login", "page": "login", "timestamp": "2026-10-09T10:00:00Z", "payload": {"username": "u1"}},
            {"action": "failed_login", "page": "login", "timestamp": "2026-10-09T10:05:00Z", "payload": {"username": "u1"}},
            {"action": "failed_login", "page": "login", "timestamp": "2026-10-09T10:10:00Z", "payload": {"username": "u1"}},
        ]
        det_spread = detector.evaluate_session(events_spread)
        self.assertIsNone(det_spread)

        # 2. Count per source_ip across different session IDs within 60s
        events_by_ip = [
            {"session_id": "sess_1", "source_ip": "198.51.100.2", "action": "failed_login", "page": "login", "timestamp": "2026-10-09T10:00:00Z", "payload": {"username": "admin"}},
            {"session_id": "sess_2", "source_ip": "198.51.100.2", "action": "failed_login", "page": "login", "timestamp": "2026-10-09T10:00:15Z", "payload": {"username": "admin"}},
            {"session_id": "sess_3", "source_ip": "198.51.100.2", "action": "failed_login", "page": "login", "timestamp": "2026-10-09T10:00:30Z", "payload": {"username": "admin"}},
        ]
        det_ip = detector.evaluate_session(events_by_ip)
        self.assertIsNotNone(det_ip)
        self.assertEqual(det_ip.attack_type, "BRUTE_FORCE")

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
        self.assertIn("RULE_SCANNING_01", detection.evidence[0])

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

    def test_sqli_obfuscation(self):
        detector = SQLInjectionDetector()

        # Mixed case
        ev_mixed = {"payload": {"query": "uNiOn sElEcT null, password fRoM credentials"}}
        det_mixed = detector.evaluate_event(ev_mixed)
        self.assertIsNotNone(det_mixed)
        self.assertEqual(det_mixed.attack_type, "SQL_INJECTION")

        # Inline comments /**/
        ev_comments = {"payload": {"query": "UNION/**/SELECT/**/1,/**/username,/**/password/**/FROM/**/users"}}
        det_comments = detector.evaluate_event(ev_comments)
        self.assertIsNotNone(det_comments)
        self.assertEqual(det_comments.attack_type, "SQL_INJECTION")

        # Auth bypass with inline comment
        ev_bypass = {"payload": {"username": "'/**/OR/**/'1'='1"}}
        det_bypass = detector.evaluate_event(ev_bypass)
        self.assertIsNotNone(det_bypass)

    def test_sqli_negative_benign_inputs(self):
        detector = SQLInjectionDetector()

        # Benign apostrophe in name / word
        ev1 = {"payload": {"username": "O'Connor"}}
        self.assertIsNone(detector.evaluate_event(ev1))

        ev2 = {"payload": {"comment": "It's a wonderful day for testing"}}
        self.assertIsNone(detector.evaluate_event(ev2))

        # Benign word "select" in normal sentences
        ev3 = {"payload": {"search": "Please select your option from the dropdown menu"}}
        self.assertIsNone(detector.evaluate_event(ev3))

        ev4 = {"payload": {"filter": "select all items where active"}}
        self.assertIsNone(detector.evaluate_event(ev4))

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

    def test_path_traversal_obfuscation(self):
        detector = PathTraversalDetector()

        # Double URL-encoding (%252e%252e%252f)
        ev_double = {"payload": {"path": "%252e%252e%252f%252e%252e%252fetc%252fpasswd"}}
        det_double = detector.evaluate_event(ev_double)
        self.assertIsNotNone(det_double)
        self.assertEqual(det_double.attack_type, "PATH_TRAVERSAL")

        # Mixed slashes and encoding
        ev_mixed = {"payload": {"file": "..%2f..%5cboot.ini"}}
        det_mixed = detector.evaluate_event(ev_mixed)
        self.assertIsNotNone(det_mixed)

    def test_path_traversal_negative_benign_text(self):
        detector = PathTraversalDetector()

        # Harmless text mentioning "../" in description
        ev1 = {"payload": {"search": "In Linux documentation, ../ represents parent directory"}}
        self.assertIsNone(detector.evaluate_event(ev1))

        ev2 = {"payload": {"query": "how to use ../ in command line"}}
        self.assertIsNone(detector.evaluate_event(ev2))

    def test_sensitive_access_detection(self):
        detector = SensitiveAccessDetector()

        # Direct access to backup page with download
        ev1 = {"page": "backup", "action": "file_download", "payload": {"file": "customer_dump.sql.gz"}}
        det1 = detector.evaluate_event(ev1)
        self.assertIsNotNone(det1)
        self.assertEqual(det1.attack_type, "SENSITIVE_ACCESS")
        self.assertIn("RULE_SENSITIVE_ACCESS_01", det1.evidence[0])

        # Harmless access to non-sensitive asset
        ev2 = {"page": "login", "action": "page_view", "payload": {}}
        det2 = detector.evaluate_event(ev2)
        self.assertIsNone(det2)

    def test_deduplication_and_out_of_order_timestamps(self):
        # Events out-of-order with duplicate event_id
        events = [
            {"event_id": "e_dup", "timestamp": "2026-10-09T10:05:00Z", "page": "database", "action": "query_submit", "payload": {"query": "' OR 1=1--"}},
            {"event_id": "e_dup", "timestamp": "2026-10-09T10:05:00Z", "page": "database", "action": "query_submit", "payload": {"query": "' OR 1=1--"}},
            {"event_id": "e_earlier", "timestamp": "2026-10-09T10:00:00Z", "page": "login", "action": "page_view"},
            {"event_id": "e_bf_1", "timestamp": "2026-10-09T10:01:00Z", "page": "login", "action": "failed_login", "payload": {"username": "admin"}},
            {"event_id": "e_bf_2", "timestamp": "2026-10-09T10:01:10Z", "page": "login", "action": "failed_login", "payload": {"username": "admin"}},
            {"event_id": "e_bf_3", "timestamp": "2026-10-09T10:01:20Z", "page": "login", "action": "failed_login", "payload": {"username": "admin"}},
        ]
        detections = self.threat_engine.evaluate_session(events)
        detected_types = {d.attack_type for d in detections}
        self.assertIn("SQL_INJECTION", detected_types)
        self.assertIn("BRUTE_FORCE", detected_types)

    def test_empty_and_missing_fields_no_raise(self):
        # Empty list
        self.assertEqual(self.threat_engine.evaluate_session([]), [])
        self.assertEqual(self.threat_engine.evaluate_event({}), [])

        # Corrupted / sparse dicts
        sparse_events = [
            {},
            {"action": None},
            {"page": None, "payload": "not_a_dict"},
            {"event_id": 12345},
        ]
        res = self.threat_engine.evaluate_session(sparse_events)
        self.assertIsInstance(res, list)


if __name__ == "__main__":
    unittest.main()
