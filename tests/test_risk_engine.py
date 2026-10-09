"""
Tests for NetDecoy Risk Scoring Engine
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
        self.assertLessEqual(res_high["score"], 100)
        self.assertGreaterEqual(res_high["score"], 0)

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


if __name__ == "__main__":
    unittest.main()
