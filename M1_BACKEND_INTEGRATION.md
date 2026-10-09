# NetDecoy --- M1 Backend & Integration Engineer

## Role

You are **M1 --- Backend and Integration Lead**.

Your responsibility is to build the central backend that connects:

**Trap Pages → Event Collector → Detection/Intelligence → Dashboard**

You own the backend API contracts, event ingestion, session tracking,
persistence, geolocation integration, integration testing, and final
backend stability.

------------------------------------------------------------------------

# 1. Critical Rules

1.  Work primarily on the `backend` branch.
2.  Do NOT modify the frontend implementation, trap UI, or intelligence
    algorithms unless integration requires a tiny contract change.
3.  Follow `shared/event_schema.json` and `shared/api_contract.md`.
4.  Never invent a second event format.
5.  Keep the backend simple and reliable.
6.  Do not build production-grade infrastructure.
7.  Do not expose a real honeypot to the public Internet.
8.  All attacker data used for the demo must be synthetic/controlled.
9.  Every API must fail gracefully.
10. Keep the server stable for the final live demo.

------------------------------------------------------------------------

# 2. Expected Repository Structure

``` text
netdecoy/
├── backend/
│   ├── app.py
│   ├── routes/
│   ├── services/
│   ├── database/
│   └── utils/
├── intelligence/
├── traps/
├── frontend/
├── shared/
│   ├── event_schema.json
│   ├── api_contract.md
│   └── attack_types.json
├── README.md
└── requirements.txt
```

Adapt this to the team's actual architecture if it already exists.

------------------------------------------------------------------------

# 3. Technology Direction

Preferred stack:

-   Python
-   Flask or FastAPI
-   SQLite for hackathon reliability unless the team explicitly decides
    otherwise
-   SQLAlchemy if useful
-   REST APIs
-   JSON event format

Do not introduce PostgreSQL, Redis, Kafka, Docker orchestration,
microservices, etc. unless absolutely necessary.

------------------------------------------------------------------------

# 4. First Task --- Establish the Event Contract

Create:

`shared/event_schema.json`

Minimum event:

``` json
{
  "event_id": "evt_001",
  "session_id": "sess_001",
  "timestamp": "2026-10-08T14:30:21",
  "source_ip": "127.0.0.1",
  "page": "login",
  "action": "failed_login",
  "event_type": "authentication",
  "payload": {}
}
```

Required fields:

-   `event_id`
-   `session_id`
-   `timestamp`
-   `source_ip`
-   `page`
-   `action`
-   `event_type`
-   `payload`

Do not make fields inconsistent between traps.

------------------------------------------------------------------------

# 5. Event Collector

Create one central function:

``` python
log_event(
    session_id,
    source_ip,
    page,
    action,
    event_type,
    payload=None
)
```

Responsibilities:

-   create event ID
-   add timestamp
-   normalize input
-   persist event
-   make event available to intelligence layer
-   avoid crashing if optional fields are missing

Every trap must use this collector.

------------------------------------------------------------------------

# 6. Session Tracking

Create a simple session mechanism.

Each visitor/attacker should have:

``` text
session_id
source_ip
first_seen
last_seen
event_count
```

The session ID should allow the system to reconstruct an attacker
journey.

------------------------------------------------------------------------

# 7. Backend APIs

Implement these APIs.

## Events

``` text
POST /api/events
GET  /api/events
```

`POST /api/events` accepts the shared event schema.

`GET /api/events` returns recent events.

Support optional filters if time permits:

``` text
session_id
severity
event_type
```

------------------------------------------------------------------------

## Statistics

``` text
GET /api/stats
```

Return:

``` json
{
  "total_events": 148,
  "total_sessions": 8,
  "threats_detected": 12,
  "high_risk": 4
}
```

------------------------------------------------------------------------

## Risk

``` text
GET /api/risk
```

Return current/session risk information.

Example:

``` json
{
  "score": 87,
  "level": "HIGH",
  "breakdown": {
    "brute_force": 20,
    "scanning": 20,
    "sql_injection": 30
  }
}
```

------------------------------------------------------------------------

## Journey

``` text
GET /api/journey
```

Return ordered attack stages/events.

------------------------------------------------------------------------

## AI Analysis

``` text
GET /api/analysis
```

Return the latest AI-generated analysis from M3.

Do not implement the AI logic yourself if M3 owns it.

------------------------------------------------------------------------

## Prediction

``` text
GET /api/prediction
```

Return:

``` json
{
  "next_stage": "Privilege Escalation",
  "confidence": 73,
  "basis": "Observed attack sequence pattern"
}
```

------------------------------------------------------------------------

## Geolocation

``` text
GET /api/geo
```

Return approximate geographic information.

If the external API fails:

``` json
{
  "available": false,
  "message": "Location unavailable"
}
```

The rest of the dashboard must continue working.

------------------------------------------------------------------------

## Reset

``` text
POST /api/reset
```

This is important for the live demo.

It should clear demo events/session state and restore a clean state.

------------------------------------------------------------------------

# 8. Geolocation

Use the selected IP geolocation API only as an enrichment service.

Never make it a critical dependency.

Pipeline:

``` text
Event
 ↓
Source IP
 ↓
Geo API
 ↓
Approximate city/country/lat/lng
 ↓
Dashboard
```

Do not claim that IP geolocation gives the attacker's exact physical
location.

------------------------------------------------------------------------

# 9. Integration with M3

M3 owns:

-   detection
-   risk
-   AI
-   prediction
-   journey logic

Your responsibility is to provide clean data to those components.

Preferred interface:

``` python
analyze_events(events)
```

or another simple agreed interface.

Document the actual interface in:

`shared/api_contract.md`

------------------------------------------------------------------------

# 10. Integration with M4

M4 will send events from six trap pages.

Make sure every trap can send:

``` text
session_id
source_ip
page
action
event_type
payload
```

Do not force M4 to understand database internals.

------------------------------------------------------------------------

# 11. Integration with M2

M2 should consume stable JSON APIs.

Do not require the frontend to directly access database files.

The frontend talks to:

``` text
/backend APIs
```

only.

------------------------------------------------------------------------

# 12. Antigravity Instructions

Use Antigravity as an implementation/debugging agent.

Good prompt:

> You are working only on the NetDecoy backend branch. Inspect the
> existing repository before modifying anything. Follow
> `shared/event_schema.json` and `shared/api_contract.md`. Implement the
> event collector and backend API requested below. Do not modify
> frontend, trap UI, or intelligence algorithms. Run the application and
> test the affected endpoints before finishing. Report files changed,
> tests performed, and any assumptions.

Bad prompt:

> Build the whole NetDecoy project.

Keep tasks small.

------------------------------------------------------------------------

# 13. MCP Usage

Use available MCP tools for:

-   repository inspection
-   file inspection
-   running/testing the application
-   browser testing
-   Git/GitHub inspection
-   database inspection if available

Do not use MCP tools unnecessarily.

If browser MCP is available, verify:

``` text
trap → event → API → dashboard
```

If GitHub MCP is available, inspect branch status before integration.

------------------------------------------------------------------------

# 14. Timeline

## 0:00--0:20

All team members:

-   architecture
-   event schema
-   API contracts

## 0:20--1:30

Build:

-   backend skeleton
-   event collector
-   session handling
-   basic API

## 1:30 checkpoint

Verify:

``` text
Trap → POST /api/events → stored event
```

## 1:30--2:45

Build:

-   remaining APIs
-   stats
-   risk integration
-   journey integration
-   reset
-   geo

## 2:45 checkpoint

Verify complete MVP pipeline.

## 2:45--4:00

Integration with M2/M3/M4.

## 4:00--5:00

Stability/testing.

## 5:00--5:30

README/backend documentation.

## 5:30--6:00

No new features. Only fixes.

------------------------------------------------------------------------

# 15. Acceptance Criteria

Backend is DONE when:

-   [ ] Server starts reliably
-   [ ] Six traps can generate events
-   [ ] Event schema is consistent
-   [ ] Events persist
-   [ ] Sessions work
-   [ ] Stats endpoint works
-   [ ] Risk endpoint works
-   [ ] Journey endpoint works
-   [ ] AI endpoint works
-   [ ] Prediction endpoint works
-   [ ] Geo failure does not break the app
-   [ ] Reset works
-   [ ] Frontend can consume all required APIs
-   [ ] Demo can be repeated from a clean state

------------------------------------------------------------------------

# 16. Commit Examples

``` text
feat: initialize backend
feat: add shared event collector
feat: add session tracking
feat: add event API
feat: add statistics API
feat: integrate threat engine
feat: add journey API
feat: add geo enrichment
feat: add reset endpoint
fix: handle unavailable geolocation
fix: stabilize event ingestion
```

------------------------------------------------------------------------

# 17. Final Responsibility

You are the final backend stability owner.

At approximately 5 hours:

**Freeze architecture.**

Do not allow last-minute architectural rewrites.

Your priority is:

**WORKING SYSTEM \> MORE FEATURES**
