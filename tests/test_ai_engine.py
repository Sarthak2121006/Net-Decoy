"""
Tests for NetDecoy AI Threat Explanation Engine
Includes mocked tests for timeout, invalid JSON, missing keys, and cache hits.
"""

import json
import os
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from intelligence.ai_engine import AIEngine


class DummyHTTPResponse:
    def __init__(self, data: bytes, status: int = 200):
        self.data = data
        self.status = status

    def read(self):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class TestAIEngine(unittest.TestCase):

    def setUp(self):
        # Initialize without external API key to test deterministic fallback
        self.ai_engine = AIEngine()

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

    @patch("urllib.request.urlopen")
    def test_mocked_client_timeout(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("Request timed out")

        with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_test_key"}):
            engine = AIEngine(timeout=0.1)
            result = engine.explain(
                session_id="sess_timeout",
                risk_score=75,
                risk_level="HIGH",
                detected_attacks=["SQL_INJECTION"],
                evidence_list=["Union select detected"]
            )

        self.assertTrue(result["is_fallback"])
        self.assertEqual(result["session_id"], "sess_timeout")
        self.assertIn("summary", result)
        self.assertTrue(mock_urlopen.called)

    @patch("urllib.request.urlopen")
    def test_mocked_client_invalid_json(self, mock_urlopen):
        mock_urlopen.return_value = DummyHTTPResponse(b"NOT_VALID_JSON_RESPONSE", status=200)

        with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_test_key"}):
            engine = AIEngine()
            result = engine.explain(
                session_id="sess_bad_json",
                risk_score=50,
                risk_level="MEDIUM",
                detected_attacks=["SCANNING"],
                evidence_list=["Probed 3 endpoints"]
            )

        self.assertTrue(result["is_fallback"])
        self.assertEqual(result["session_id"], "sess_bad_json")

    @patch("urllib.request.urlopen")
    def test_mocked_client_missing_keys(self, mock_urlopen):
        # Missing 'recommended_actions' and 'evidence'
        gemini_response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps({
                                    "summary": "Attacker performed scanning.",
                                    "likely_intent": "Enumeration."
                                })
                            }
                        ]
                    }
                }
            ]
        }
        mock_urlopen.return_value = DummyHTTPResponse(json.dumps(gemini_response).encode("utf-8"), status=200)

        with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_test_key"}):
            engine = AIEngine()
            result = engine.explain(
                session_id="sess_missing_keys",
                risk_score=50,
                risk_level="MEDIUM",
                detected_attacks=["SCANNING"],
                evidence_list=["Probed 3 endpoints"]
            )

        # Must fall back because response schema is missing required keys
        self.assertTrue(result["is_fallback"])
        self.assertIn("recommended_actions", result)
        self.assertIn("evidence", result)

    @patch("urllib.request.urlopen")
    def test_mocked_client_success_and_cache_hit(self, mock_urlopen):
        valid_llm_json = {
            "summary": "Attacker probed database and executed SQL injection.",
            "likely_intent": "Privilege escalation and database extraction.",
            "evidence": ["Union select observed in query parameter"],
            "recommended_actions": ["Block IP address and enforce parameterized queries"]
        }
        gemini_response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": json.dumps(valid_llm_json)}
                        ]
                    }
                }
            ]
        }
        mock_urlopen.return_value = DummyHTTPResponse(json.dumps(gemini_response).encode("utf-8"), status=200)

        with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_test_key"}):
            engine = AIEngine()
            # First call -> hits mock
            res1 = engine.explain(
                session_id="sess_cache_test",
                risk_score=80,
                risk_level="CRITICAL",
                detected_attacks=["SQL_INJECTION"],
                evidence_list=["Union select observed"],
                event_count=5
            )
            self.assertFalse(res1["is_fallback"])
            self.assertEqual(res1["summary"], valid_llm_json["summary"])
            self.assertEqual(mock_urlopen.call_count, 1)

            # Second call with same (session_id, event_count) -> hits cache!
            res2 = engine.explain(
                session_id="sess_cache_test",
                risk_score=80,
                risk_level="CRITICAL",
                detected_attacks=["SQL_INJECTION"],
                evidence_list=["Union select observed"],
                event_count=5
            )
            self.assertTrue(res2.get("cached"))
            self.assertEqual(mock_urlopen.call_count, 1)  # urlopen was NOT called again


if __name__ == "__main__":
    unittest.main()
