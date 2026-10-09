"""
Tests for NetDecoy Risk Scoring Engine
Includes boundary tests at 29/30, 59/60, 79/80 and capped boolean verification.
"""

import unittest
from intelligence.risk_engine import RiskEngine
from intelligence.threat_engine import AttackDetection


class TestRiskEngine(unittest.TestCase):

    def setUp(self):
        self.risk_engine = RiskEngine()

    def test_risk_score_bounds(self):
        # Empty detections -> 0 score, LOW level
        res_empty = self.risk_engine.calculate_risk([])
        self.assertEqual(res_empty["score"], 0)
        self.assertEqual(res_empty["level"], "LOW")
        self.assertEqual(res_empty["breakdown"], {})
        self.assertFalse(res_empty["capped"])

        # Massive detections -> capped at 100
        detections = [
            AttackDetection("BRUTE_FORCE", True, "HIGH", ["evidence 1"]),
            AttackDetection("SCANNING", True, "HIGH", ["evidence 2"]),
            AttackDetection("SQL_INJECTION", True, "HIGH", ["evidence 3"]),
            AttackDetection("PATH_TRAVERSAL", True, "HIGH", ["evidence 4"]),
            AttackDetection("SENSITIVE_ACCESS", True, "HIGH", ["evidence 5"]),
            AttackDetection("REPEATED_SUSPICIOUS", True, "HIGH", ["evidence 6"]),
        ]
        res_high = self.risk_engine.calculate_risk(detections, event_count=20)
        self.assertEqual(res_high["score"], 100)
        self.assertEqual(res_high["level"], "CRITICAL")
        self.assertTrue(res_high["capped"])
        self.assertLessEqual(res_high["score"], 100)
        self.assertGreaterEqual(res_high["score"], 0)

    def test_boundary_levels_29_30_59_60_79_80(self):
        self.assertEqual(self.risk_engine.calculate_level(0), "LOW")
        self.assertEqual(self.risk_engine.calculate_level(29), "LOW")
        self.assertEqual(self.risk_engine.calculate_level(30), "MEDIUM")
        self.assertEqual(self.risk_engine.calculate_level(59), "MEDIUM")
        self.assertEqual(self.risk_engine.calculate_level(60), "HIGH")
        self.assertEqual(self.risk_engine.calculate_level(79), "HIGH")
        self.assertEqual(self.risk_engine.calculate_level(80), "CRITICAL")
        self.assertEqual(self.risk_engine.calculate_level(100), "CRITICAL")

    def test_capped_boolean_and_raw_breakdown(self):
        # 1. Under 100
        detections_sub100 = [
            AttackDetection("BRUTE_FORCE", True, "HIGH", ["evidence"]),  # 20
            AttackDetection("SQL_INJECTION", True, "HIGH", ["evidence"]),  # 30
        ]
        res1 = self.risk_engine.calculate_risk(detections_sub100)
        self.assertEqual(res1["score"], 50)
        self.assertFalse(res1["capped"])
        self.assertEqual(res1["breakdown"]["brute_force"], 20)
        self.assertEqual(res1["breakdown"]["sql_injection"], 30)

        # 2. Over 100: Brute Force (20) + Scanning (20) + SQLi (30) + Path Traversal (30) + Sensitive Access (20) = 120
        detections_over100 = [
            AttackDetection("BRUTE_FORCE", True, "HIGH", ["evidence"]),
            AttackDetection("SCANNING", True, "HIGH", ["evidence"]),
            AttackDetection("SQL_INJECTION", True, "HIGH", ["evidence"]),
            AttackDetection("PATH_TRAVERSAL", True, "HIGH", ["evidence"]),
            AttackDetection("SENSITIVE_ACCESS", True, "HIGH", ["evidence"]),
        ]
        res2 = self.risk_engine.calculate_risk(detections_over100)
        self.assertEqual(res2["score"], 100)
        self.assertTrue(res2["capped"])
        # Breakdown keeps raw weights
        raw_sum = sum(res2["breakdown"].values())
        self.assertEqual(raw_sum, 120)
        self.assertEqual(res2["breakdown"]["brute_force"], 20)
        self.assertEqual(res2["breakdown"]["scanning"], 20)
        self.assertEqual(res2["breakdown"]["sql_injection"], 30)
        self.assertEqual(res2["breakdown"]["path_traversal"], 30)
        self.assertEqual(res2["breakdown"]["sensitive_access"], 20)

    def test_idempotence_and_read_safety(self):
        detections = [
            AttackDetection("BRUTE_FORCE", True, "MEDIUM", ["evidence"]),
            AttackDetection("SCANNING", True, "MEDIUM", ["evidence"]),
        ]
        res1 = self.risk_engine.calculate_risk(detections, session_id="s1")
        res2 = self.risk_engine.calculate_risk(detections, session_id="s1")
        # Reading repeated times does not compound
        self.assertEqual(res1["score"], res2["score"])
        self.assertEqual(res1["score"], 40)
        self.assertEqual(res1["level"], "MEDIUM")
        self.assertEqual(res1["capped"], res2["capped"])

    def test_risk_breakdown_explainability(self):
        detections = [
            {"attack_type": "SQL_INJECTION", "evidence": ["union select"], "severity": "HIGH"},
            {"attack_type": "SENSITIVE_ACCESS", "evidence": ["backup download"], "severity": "HIGH"},
        ]
        res = self.risk_engine.calculate_risk(detections)
        self.assertEqual(res["score"], 50)
        self.assertEqual(res["breakdown"]["sql_injection"], 30)
        self.assertEqual(res["breakdown"]["sensitive_access"], 20)
        self.assertEqual(len(res["signals"]), 2)
        self.assertFalse(res["capped"])


if __name__ == "__main__":
    unittest.main()
