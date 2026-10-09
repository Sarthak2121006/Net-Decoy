"""
Tests for NetDecoy Prediction Engine
"""

import unittest
from intelligence.prediction_engine import PredictionEngine


class TestPredictionEngine(unittest.TestCase):

    def setUp(self):
        self.prediction_engine = PredictionEngine()

    def test_reconnaissance_prediction(self):
        res = self.prediction_engine.predict_next_stage("RECONNAISSANCE")
        self.assertEqual(res["current_stage"], "RECONNAISSANCE")
        self.assertEqual(res["next_stage"], "SCANNING")
        self.assertGreaterEqual(res["confidence"], 80)
        self.assertEqual(res["confidence_label"], "Pattern confidence")
        self.assertIn("SCANNING", res["basis"])

    def test_credential_access_prediction(self):
        res = self.prediction_engine.predict_next_stage(
            "CREDENTIAL_ACCESS",
            visited_stages=["RECONNAISSANCE", "SCANNING", "CREDENTIAL_ACCESS"]
        )
        self.assertEqual(res["current_stage"], "CREDENTIAL_ACCESS")
        self.assertEqual(res["next_stage"], "PRIVILEGE_ESCALATION")
        # Boosted by history sequence depth
        self.assertGreaterEqual(res["confidence"], 73)
        self.assertIn("PRIVILEGE_ESCALATION", res["basis"])

    def test_privilege_escalation_prediction(self):
        res = self.prediction_engine.predict_next_stage("PRIVILEGE_ESCALATION")
        self.assertEqual(res["current_stage"], "PRIVILEGE_ESCALATION")
        self.assertEqual(res["next_stage"], "DATA_ACCESS")
        self.assertIn("DATA_ACCESS", res["basis"])
        self.assertIn("backup", res["potential_targets"])

    def test_unknown_stage_safe_fallback(self):
        res = self.prediction_engine.predict_next_stage("NON_EXISTENT_STAGE")
        self.assertEqual(res["confidence_label"], "Pattern confidence")
        self.assertIn("next_stage", res)
        self.assertTrue(0 <= res["confidence"] <= 100)


if __name__ == "__main__":
    unittest.main()
