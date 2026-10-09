"""
Tests for Event Contract and Schema Validation
Validates real events in tests/fixtures/real_events/ against shared/event_schema.json
and ensures analyze_session executes without errors.
"""

import json
import os
import unittest
from pathlib import Path
from intelligence import analyze_session


class TestEventContract(unittest.TestCase):

    def setUp(self):
        self.repo_root = Path(__file__).resolve().parent.parent
        self.schema_path = self.repo_root / "shared" / "event_schema.json"
        self.fixtures_dir = self.repo_root / "tests" / "fixtures" / "real_events"

        self.assertTrue(self.schema_path.exists(), f"Schema file not found at {self.schema_path}")
        with open(self.schema_path, "r", encoding="utf-8") as f:
            self.schema = json.load(f)

    def _validate_event_against_schema(self, event, file_name, index):
        """Validates a single event against shared/event_schema.json rules without external dependencies."""
        self.assertIsInstance(event, dict, f"Event #{index} in {file_name} must be a JSON object")

        # Required fields
        required_fields = self.schema.get("required", [])
        for field in required_fields:
            self.assertIn(
                field,
                event,
                f"Missing required field '{field}' in event #{index} of {file_name}"
            )
            val = event[field]
            self.assertIsInstance(
                val,
                str,
                f"Field '{field}' in event #{index} of {file_name} must be a string, got {type(val)}"
            )
            self.assertTrue(
                len(val.strip()) > 0,
                f"Field '{field}' in event #{index} of {file_name} cannot be empty"
            )

        # Enum validations
        properties = self.schema.get("properties", {})
        
        # page enum
        valid_pages = properties.get("page", {}).get("enum", [])
        if valid_pages:
            self.assertIn(
                event["page"],
                valid_pages,
                f"Invalid page '{event['page']}' in {file_name} #{index}. Allowed: {valid_pages}"
            )

        # event_type enum
        valid_types = properties.get("event_type", {}).get("enum", [])
        if valid_types:
            self.assertIn(
                event["event_type"],
                valid_types,
                f"Invalid event_type '{event['event_type']}' in {file_name} #{index}. Allowed: {valid_types}"
            )

        # payload type
        if "payload" in event:
            self.assertIsInstance(
                event["payload"],
                dict,
                f"Field 'payload' in event #{index} of {file_name} must be an object/dict"
            )

    def test_fixtures_schema_and_pipeline(self):
        self.assertTrue(self.fixtures_dir.exists(), f"Fixtures directory not found: {self.fixtures_dir}")
        json_files = list(self.fixtures_dir.glob("*.json"))

        self.assertTrue(
            len(json_files) > 0,
            f"No JSON fixture files found in {self.fixtures_dir}. Drop real trap events here."
        )

        for json_file in json_files:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                events = [data]
            elif isinstance(data, list):
                events = data
            else:
                self.fail(f"File {json_file.name} must contain a JSON object or array of objects")

            # Validate each event against the schema
            for idx, event in enumerate(events):
                self._validate_event_against_schema(event, json_file.name, idx)

            # Run analyze_session on the events without error
            session_id = events[0].get("session_id", "fixture_session") if events else "fixture_session"
            result = analyze_session(events, session_id=session_id)
            self.assertIsInstance(result, dict)
            self.assertEqual(result["session_id"], session_id)
            self.assertIn("risk", result)
            self.assertIn("journey", result)
            self.assertIn("prediction", result)
            self.assertIn("ai_analysis", result)


if __name__ == "__main__":
    unittest.main()
