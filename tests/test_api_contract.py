"""
Tests for API Contract Conformance
Verifies that keys in shared/sample_analysis.json strictly match
the schemas and keys documented in shared/api_contract.md.
"""

import json
import re
import unittest
from pathlib import Path


class TestApiContractKeys(unittest.TestCase):

    def setUp(self):
        self.repo_root = Path(__file__).resolve().parent.parent
        self.contract_path = self.repo_root / "shared" / "api_contract.md"
        self.sample_analysis_path = self.repo_root / "shared" / "sample_analysis.json"

        self.assertTrue(self.contract_path.exists(), f"Contract file missing: {self.contract_path}")
        self.assertTrue(self.sample_analysis_path.exists(), f"Sample analysis missing: {self.sample_analysis_path}")

        with open(self.contract_path, "r", encoding="utf-8") as f:
            self.contract_text = f.read()

        with open(self.sample_analysis_path, "r", encoding="utf-8") as f:
            self.sample_analysis = json.load(f)

    def _extract_section_json(self, section_title_regex: str) -> dict:
        """Finds a section in api_contract.md and extracts the first JSON code block."""
        match = re.search(section_title_regex + r".*?```json\s*(.*?)\s*```", self.contract_text, re.DOTALL)
        self.assertIsNotNone(match, f"Could not find JSON block in contract under {section_title_regex}")
        json_str = match.group(1)
        return json.loads(json_str)

    def test_sample_analysis_top_level_keys(self):
        contract_unified = self._extract_section_json(r"## 6\.\s+Unified Session Analysis")
        expected_keys = set(contract_unified.keys())
        actual_keys = set(self.sample_analysis.keys())

        diff = expected_keys.symmetric_difference(actual_keys)
        self.assertEqual(
            actual_keys,
            expected_keys,
            f"Keys in sample_analysis.json differ from api_contract.md Section 6. Difference: {diff}"
        )

    def test_risk_keys(self):
        contract_risk = self._extract_section_json(r"## 2\.\s+Risk Score & Breakdown")
        expected_keys = set(contract_risk.keys())
        actual_keys = set(self.sample_analysis["risk"].keys())

        diff = expected_keys.symmetric_difference(actual_keys)
        self.assertEqual(
            actual_keys,
            expected_keys,
            f"Keys in sample_analysis.json['risk'] differ from api_contract.md Section 2. Difference: {diff}"
        )

    def test_journey_keys(self):
        contract_journey = self._extract_section_json(r"## 3\.\s+Attacker Journey")
        expected_keys = set(contract_journey.keys())
        actual_keys = set(self.sample_analysis["journey"].keys())

        diff = expected_keys.symmetric_difference(actual_keys)
        self.assertEqual(
            actual_keys,
            expected_keys,
            f"Keys in sample_analysis.json['journey'] differ from api_contract.md Section 3. Difference: {diff}"
        )

    def test_ai_analysis_keys(self):
        contract_analysis = self._extract_section_json(r"## 4\.\s+AI Threat Analysis")
        expected_keys = set(contract_analysis.keys())
        actual_keys = set(self.sample_analysis["ai_analysis"].keys())

        diff = expected_keys.symmetric_difference(actual_keys)
        self.assertEqual(
            actual_keys,
            expected_keys,
            f"Keys in sample_analysis.json['ai_analysis'] differ from api_contract.md Section 4. Difference: {diff}"
        )

    def test_prediction_keys(self):
        contract_prediction = self._extract_section_json(r"## 5\.\s+Next-Stage Estimation")
        expected_keys = set(contract_prediction.keys())
        actual_keys = set(self.sample_analysis["prediction"].keys())

        diff = expected_keys.symmetric_difference(actual_keys)
        self.assertEqual(
            actual_keys,
            expected_keys,
            f"Keys in sample_analysis.json['prediction'] differ from api_contract.md Section 5. Difference: {diff}"
        )


if __name__ == "__main__":
    unittest.main()
