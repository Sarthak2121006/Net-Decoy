"""
Tests for NetDecoy AI Threat Explanation Engine
"""

import unittest
from intelligence.ai_engine import AIEngine


class TestAIEngine(unittest.TestCase):

    def setUp(self):
        # Initialize without external API key to test deterministic fallback
        self.ai_engine = AIEngine(api_key=None)

    def test_deterministic_fallback_generation(self):
        result = self.ai_engine.explain(
            session_id="sess_demo",
            risk_score=85,
            risk_level="CRITICAL",
            detected_attacks=["BRUTE_FORCE", "SQL_INJECTION", "SENSITIVE_ACCESS"],
            evidence_list=[
                "5 failed logins observed",
                "Union select found in query",
                "Attempted download on backup portal"
            ]
        )

        self.assertTrue(result["is_fallback"])
        self.assertEqual(result["session_id"], "sess_demo")
        self.assertIn("summary", result)
        self.assertIn("likely_intent", result)
        self.assertIn("evidence", result)
        self.assertIn("recommended_actions", result)

        # Check content quality
        self.assertIn("CRITICAL", result["summary"])
        self.assertIn("credential stuffing", result["likely_intent"])
        self.assertIn("database authorization bypass", result["likely_intent"])
        self.assertTrue(len(result["evidence"]) >= 3)
        self.assertTrue(len(result["recommended_actions"]) >= 2)

    def test_empty_attacks_fallback(self):
        result = self.ai_engine.explain(
            session_id="sess_clean",
            risk_score=10,
            risk_level="LOW",
            detected_attacks=[],
            evidence_list=[]
        )
        self.assertTrue(result["is_fallback"])
        self.assertIn("preliminary navigation", result["summary"])
        self.assertIn("LOW", result["summary"])


if __name__ == "__main__":
    unittest.main()
