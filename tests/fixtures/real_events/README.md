# Real Events Test Fixtures

Teammates (M4 - Deception and trap engineer): Drop real trap output JSON files into this directory (`tests/fixtures/real_events/`).

### Requirements:
- Each `.json` file can contain either a single event object or a JSON array of event objects.
- All events must conform to `shared/event_schema.json`:
  - `event_id` (string)
  - `session_id` (string)
  - `timestamp` (ISO 8601 date-time string)
  - `source_ip` (string)
  - `page` (enum: `"login"`, `"admin"`, `"backup"`, `"database"`, `"api"`, `"search"`)
  - `action` (string)
  - `event_type` (enum: `"authentication"`, `"navigation"`, `"database_query"`, `"file_access"`, `"api_call"`, `"input_submission"`)
  - `payload` (object, optional/default `{}`)

The automated contract test in `tests/test_contract.py` will load every `.json` file in this folder, validate the events against `shared/event_schema.json`, and verify that `intelligence.analyze_session` runs on them cleanly without error.
