# NetDecoy

### From Attacker Activity to Actionable Threat Intelligence

> **NetDecoy** is a controlled, AI-assisted deception and
> threat-intelligence prototype. It observes simulated attacker
> interactions, detects suspicious patterns, builds an attacker journey,
> explains the evidence, and estimates a possible next attack stage.

**Project:** NetDecoy\
**Event:** IEEE SYNAPSE 2026\
**Status:** Prototype / implementation in progress --- update this
status to reflect the final build.\
**Safety model:** Controlled simulation using synthetic resources and
data.

## Table of Contents

-   [Overview](#overview)
-   [Problem Statement](#problem-statement)
-   [Solution](#solution)
-   [Architecture](#architecture)
-   [How It Works](#how-it-works)
-   [Deception Modules](#deception-modules)
-   [Event Schema](#event-schema)
-   [Detection Engine](#detection-engine)
-   [Risk Scoring](#risk-scoring)
-   [Attacker Journey](#attacker-journey)
-   [AI Explanation](#ai-explanation)
-   [Next-Stage Estimation](#next-stage-estimation)
-   [Geolocation](#geolocation)
-   [SOC Dashboard](#soc-dashboard)
-   [Technology Stack](#technology-stack)
-   [Repository Structure](#repository-structure)
-   [API Reference](#api-reference)
-   [Team Responsibilities](#team-responsibilities)
-   [Hackathon Plan](#hackathon-plan)
-   [Getting Started](#getting-started)
-   [Demo Scenario](#demo-scenario)
-   [Testing Checklist](#testing-checklist)
-   [Security Boundaries](#security-boundaries)
-   [Limitations](#limitations)
-   [Future Scope](#future-scope)
-   [Git Workflow](#git-workflow)
-   [Demo Pitch](#demo-pitch)

## Overview

Security systems can generate large amounts of events and alerts.
Individual events do not always make it easy to understand how an
attacker behaves or how separate actions relate to one another.

NetDecoy demonstrates a **behavior-to-intelligence pipeline**:

**Deceive → Observe → Detect → Score → Understand → Anticipate**

It presents six simulated enterprise resources. Interactions are
recorded as structured events. A deterministic detection layer
identifies configured suspicious patterns and calculates an explainable
risk score. The system organizes observed activity into an attacker
journey, uses AI to explain the evidence, and estimates a possible next
stage using predefined behavior patterns.

NetDecoy is an educational hackathon prototype, not a replacement for a
production SIEM, SOC, or professionally operated honeypot.

## Problem Statement

Security analysts may need to determine what suspicious actions
occurred, which actions belong to the same session, how serious the
activity is, how it progressed across resources, what evidence supports
an assessment, and what should be investigated next.

A workflow focused only on collecting honeypot logs can leave the
analyst to connect the dots manually.

**Problem statement:** How can interactions with a controlled deceptive
environment be converted into understandable, explainable, and useful
threat intelligence?

## Solution

NetDecoy combines: 1. **Deception layer:** simulated login, admin,
backup, database, API, and search/file resources. 2. **Event
collector:** normalizes interactions into one shared event format. 3.
**Detection engine:** uses deterministic rules to identify configured
suspicious patterns. 4. **Threat intelligence:** calculates risk and
organizes observed actions into a journey. 5. **AI and pattern
analysis:** explains evidence and estimates a possible next stage. 6.
**SOC dashboard:** presents events, risk, journey, approximate
geolocation when available, explanation, and estimation.

The key idea is to connect observed actions into an evolving profile
rather than displaying isolated alerts.

## Architecture

``` mermaid
flowchart TD
    A[Simulated Attacker] --> B[Deception Layer]
    B --> B1[Corporate Login]
    B --> B2[Admin Dashboard]
    B --> B3[Backup Portal]
    B --> B4[Database Console]
    B --> B5[Internal API Explorer]
    B --> B6[Search / File Portal]

    B1 --> C[Central Event Collector]
    B2 --> C
    B3 --> C
    B4 --> C
    B5 --> C
    B6 --> C

    C --> D[Event Validation and Storage]
    D --> E[Deterministic Detection Engine]
    E --> F[Risk Scoring Engine]
    E --> G[Attack Journey Engine]
    E --> H[Structured Evidence]
    H --> I[AI Explanation Engine]
    G --> J[Pattern-Based Next-Stage Estimation]
    C --> K[Optional IP Geolocation]
    D --> L[Backend API]
    F --> L
    G --> L
    I --> L
    J --> L
    K --> L
    L --> M[SOC Dashboard]
```

### Component responsibilities

  -----------------------------------------------------------------------
  Component                           Responsibility
  ----------------------------------- -----------------------------------
  Deception layer                     Presents controlled fake resources
                                      and records interactions

  Event collector                     Validates and normalizes events

  Event storage                       Makes events available for analysis
                                      and dashboard queries

  Detection engine                    Applies deterministic rules

  Risk engine                         Calculates a bounded, explainable
                                      score

  Journey engine                      Organizes observed events into a
                                      readable sequence

  AI explanation engine               Summarizes evidence and suggests
                                      investigation steps

  Next-stage estimator                Uses predefined transitions to
                                      estimate a possible next stage

  Geolocation adapter                 Retrieves approximate location
                                      where available

  Backend API                         Exposes events and analysis to the
                                      dashboard

  SOC dashboard                       Presents the threat profile
  -----------------------------------------------------------------------

### Design principles

-   Keep detection separate from AI interpretation.
-   Use one shared event schema across all traps.
-   Let the frontend communicate with the backend API, not directly with
    the database.
-   Make optional external services fail gracefully.
-   Make risk assessments explainable.
-   Prefer a small, testable end-to-end system over feature bloat.

## How It Works

1.  A user interacts with a simulated enterprise resource.
2.  The resource sends a structured event to the collector.
3.  The collector validates and stores the event.
4.  The detection engine evaluates the event and relevant session
    activity.
5.  The risk engine updates the score using configured rules.
6.  The journey engine updates the observed action sequence.
7.  Structured evidence can be sent to the AI explanation engine.
8.  The pattern-based estimator checks the observed stages against
    predefined transitions.
9.  The backend API exposes results.
10. The dashboard refreshes and displays the updated profile.

Periodic polling can be used for a simple prototype. WebSockets or
streaming infrastructure can be considered later.

## Deception Modules

These are controlled decoys, not production systems.

  --------------------------------------------------------------------------
  Module            Example route     Example           Intended observation
                                      interaction       
  ----------------- ----------------- ----------------- --------------------
  Corporate Login   `/login`          Repeated failed   Brute-force pattern
                                      login attempts    

  Admin Dashboard   `/admin`          Exploring         Scanning/resource
                                      administrative    enumeration
                                      sections          

  Backup Portal     `/backup`         Opening a         Sensitive-resource
                                      synthetic backup  access
                                      resource          

  Database Console  `/database`       Submitting        SQL-injection
                                      suspicious        pattern
                                      SQL-like text     

  Internal API      `/api`            Probing fake      Endpoint enumeration
  Explorer                            endpoints         

  Search/File       `/search`         Submitting a      Path-traversal
  Portal                              traversal-like    pattern
                                      string            
  --------------------------------------------------------------------------

### Safety behavior

-   Login attempts are recorded; they do not authenticate against real
    accounts.
-   Admin content and backup files are synthetic.
-   SQL-like input is detected and logged, never executed.
-   Traversal-like input is detected and logged, never used to access
    the host filesystem.
-   Arbitrary commands are not executed.

## Event Schema

All traps should use a common schema. The backend may generate
identifiers, timestamps, and source information where appropriate.

``` json
{
  "event_id": "evt_001",
  "session_id": "sess_001",
  "timestamp": "2026-10-08T14:30:21Z",
  "source_ip": "127.0.0.1",
  "page": "login",
  "action": "failed_login",
  "event_type": "authentication",
  "payload": {
    "username": "admin"
  }
}
```

  -----------------------------------------------------------------------
  Field                               Meaning
  ----------------------------------- -----------------------------------
  `event_id`                          Unique event identifier

  `session_id`                        Identifier for grouping related
                                      activity

  `timestamp`                         Event time, preferably ISO 8601

  `source_ip`                         Address observed by the
                                      application; may be a proxy or
                                      local address

  `page`                              Resource where the event occurred

  `action`                            Specific interaction

  `event_type`                        Broad event category

  `payload`                           Additional structured context; do
                                      not put secrets here
  -----------------------------------------------------------------------

Keep action names consistent across traps, backend, and intelligence
modules. Store the shared schema in `shared/event_schema.json`.

## Detection Engine

Detection is deterministic and rule-based for the supported patterns.

  -----------------------------------------------------------------------
  Category                Example evidence        Example logic
  ----------------------- ----------------------- -----------------------
  Brute force             Multiple failed logins  Count failed attempts
                                                  per session or source
                                                  in a configured
                                                  interval

  Scanning                Probing different       Count distinct
                          resources               endpoints touched
                                                  within a time window

  SQL-injection pattern   Suspicious SQL-like     Match a documented set
                          input                   of suspicious input
                                                  patterns

  Path-traversal pattern  Traversal-like sequence Detect the pattern
                          such as `../`           without resolving or
                                                  opening a path

  Sensitive-resource      Interaction with a      Record the event and
  access                  synthetic decoy         apply the configured
                                                  rule
  -----------------------------------------------------------------------

These rules identify configured patterns; they do not prove malicious
intent in every real-world situation. Thresholds should be documented
and tested.

**AI does not decide whether an attack occurred.** The detection engine
produces evidence; AI explains it.

## Risk Scoring

NetDecoy uses a bounded score from **0 to 100**. The score should be
deterministic and accompanied by reasons.

The following are **illustrative starting weights**, not validated
security measurements:

  Signal                           Example points
  ------------------------------ ----------------
  Brute-force pattern                         +20
  Scanning pattern                            +20
  SQL-injection pattern                       +30
  Path-traversal pattern                      +30
  Sensitive-resource access                   +20
  Repeated suspicious behavior                +10

Cap the score at 100. Decide whether scoring is per event, per session,
or both, and ensure repeated API reads do not accidentally increase it.

Example severity bands:

      Score Label
  --------- ----------
      0--29 Low
     30--59 Medium
     60--79 High
    80--100 Critical

These are prototype defaults, not an industry-standard scale.

## Attacker Journey

NetDecoy connects observed interactions into a sequence.

``` text
LOGIN
  │  Multiple failed login attempts
  ▼
ADMIN
  │  Resource enumeration
  ▼
DATABASE
  │  Suspicious SQL-like input
  ▼
BACKUP
  │  Synthetic sensitive-resource access
  ▼
SEARCH / API
     Traversal pattern or endpoint probing
```

A broader illustrative stage model is:

``` text
Reconnaissance → Scanning → Credential Access → Privilege Escalation → Data Access
```

Only show stages supported by the implemented mapping and observed
events. Inferred stages must not be presented as confirmed facts.

## AI Explanation

The AI explanation engine interprets structured evidence produced by
deterministic components.

Example input:

``` json
{
  "attack_type": "SQL Injection",
  "risk_score": 72,
  "session_id": "sess_001",
  "evidence": [
    "Suspicious SQL-like input was submitted to the database decoy",
    "The session previously explored administrative resources"
  ]
}
```

Illustrative output: - **Observed behavior:** A suspicious SQL-like
pattern was submitted to the database decoy. - **Context:** The same
session previously explored administrative resources. - **Possible
intent:** The behavior may indicate an attempt to manipulate a database
query. - **Suggested investigation:** Review subsequent database and
resource-access events.

Reliability rules: - Supply only relevant structured evidence. -
Instruct the model not to invent events or certainty. - Do not let AI
independently determine security-critical detections. - Handle provider
errors, rate limits, and missing API keys. - Provide a fallback
explanation based on rule output. - Keep API keys server-side and out of
source control.

## Next-Stage Estimation

The estimator uses predefined transitions to estimate what stage might
follow observed behavior.

``` text
Observed: Scanning → Credential Access
                         │
                         ▼
Estimated next stage: Privilege Escalation
```

Show a **pattern confidence** value only if the implementation defines
and documents how it is calculated. Do not invent percentages or
describe a heuristic score as a calibrated probability. This is an
estimate, not a guarantee.

## Geolocation

An optional IP geolocation provider may return approximate country,
region, city, or coordinates.

``` text
Observed IP → Geolocation provider → Approximate location → Dashboard
```

IP geolocation is not an exact physical location. VPNs, proxies, mobile
networks, and provider coverage can affect accuracy. Local/private IPs
may not have meaningful public geolocation. Provider failures must not
stop event collection, detection, or risk scoring. Check the provider's
terms, limits, and privacy policy.

## SOC Dashboard

Suggested sections: 1. **Summary cards:** total events, active sessions,
detected patterns, current risk. 2. **Live event feed:** timestamp,
resource, action, category, severity. 3. **Risk panel:** score,
severity, and contributing signals. 4. **Attacker journey:**
chronological observed actions or mapped stages. 5. **Geographic view:**
approximate location when available. 6. **AI analysis:** evidence
summary, possible intent, investigation recommendation. 7. **Next-stage
estimate:** possible next stage and basis for the estimate. 8. **Demo
reset:** controlled reset of sample/session state, if implemented.

Include loading, empty, and error states for optional services and
endpoints.

## Technology Stack

The final stack must match the actual repository. This is a proposed
lightweight stack; update it after implementation.

  -----------------------------------------------------------------------
  Layer                               Proposed technology
  ----------------------------------- -----------------------------------
  Backend                             Python with FastAPI or Flask

  Frontend                            HTML, CSS, JavaScript

  Event storage                       SQLite or another lightweight local
                                      store

  AI explanation                      Server-side LLM API integration, if
                                      configured

  Geolocation                         Optional external IP geolocation
                                      API

  Visualization                       JavaScript dashboard components and
                                      optional map library

  Version control                     Git and GitHub

  Development assistance              Antigravity and available MCP tools
  -----------------------------------------------------------------------

Do not claim a tool is implemented simply because it is planned. Replace
alternatives with the exact framework and versions used.

## Repository Structure

Proposed structure:

``` text
netdecoy/
├── backend/
│   ├── app.py
│   ├── routes/
│   ├── services/
│   ├── database/
│   └── utils/
├── intelligence/
│   ├── threat_engine.py
│   ├── risk_engine.py
│   ├── ai_engine.py
│   ├── prediction_engine.py
│   └── journey_engine.py
├── traps/
│   ├── login/
│   ├── admin/
│   ├── backup/
│   ├── database/
│   ├── api/
│   ├── search/
│   └── assets/
├── frontend/
│   ├── dashboard.html
│   ├── dashboard.css
│   ├── dashboard.js
│   └── components/
├── shared/
│   ├── event_schema.json
│   ├── api_contract.md
│   └── attack_types.json
├── architecture.md
├── README.md
└── requirements.txt
```

The actual repository may differ. Keep this section synchronized with
the real project.

## API Reference

These are **planned endpoints**. Update the table to reflect implemented
routes, request/response formats, and any authentication requirements.

  Method   Endpoint            Purpose
  -------- ------------------- -----------------------------------------------
  `GET`    `/health`           Check backend availability
  `POST`   `/api/events`       Validate and record an event
  `GET`    `/api/events`       Retrieve events
  `GET`    `/api/stats`        Return dashboard statistics
  `GET`    `/api/risk`         Return score and supporting signals
  `GET`    `/api/journey`      Return observed journey
  `GET`    `/api/analysis`     Return AI explanation or fallback
  `GET`    `/api/prediction`   Return next-stage estimate
  `GET`    `/api/geo`          Return approximate geolocation when available
  `POST`   `/api/reset`        Reset demo state, if supported

API principles: - Use the shared event schema. - Return consistent JSON
and appropriate HTTP status codes. - Validate inputs on the server. -
Never return secrets. - Optional AI/geolocation failures must not take
down core endpoints. - Document empty, unavailable, and error responses.

## Team Responsibilities

  -----------------------------------------------------------------------
  Member                  Role                    Ownership
  ----------------------- ----------------------- -----------------------
  M1                      Backend and integration Backend, event
                          lead                    collector, storage, API
                                                  contracts, integration

  M2                      Frontend and dashboard  Dashboard, event feed,
                          lead                    risk, journey, AI
                                                  panel, visualization

  M3                      Intelligence and AI     Detection, risk
                          lead                    scoring, journey
                                                  mapping, AI
                                                  explanation, estimation

  M4                      Deception and trap      Six simulated resources
                          engineer                and event generation
  -----------------------------------------------------------------------

All members should agree on shared contracts, work on assigned branches,
commit frequently, integrate early, and test the full flow.

## Hackathon Plan

Proposed six-hour schedule; adjust to the organizer's actual schedule.

  -----------------------------------------------------------------------
  Time from start                     Goal
  ----------------------------------- -----------------------------------
  0:00--0:20                          Confirm requirements, architecture,
                                      schema, API contract, branches,
                                      demo

  0:20--1:30                          Backend foundation, dashboard
                                      skeleton, detection/risk logic,
                                      first trap

  1:30--2:45                          APIs, frontend connection, journey
                                      logic, remaining traps

  Around 3:00                         MVP: trap → event → detection →
                                      risk → dashboard

  3:00--4:00                          Integrate AI explanation, journey,
                                      estimation, and geolocation if
                                      feasible

  4:00--5:00                          End-to-end tests, integration
                                      fixes, demo sequence

  5:00--5:30                          README, screenshots, repository
                                      checks

  5:30--6:00                          Feature freeze, bug fixes, demo
                                      rehearsal
  -----------------------------------------------------------------------

**MVP priority:** A reliable end-to-end pipeline matters more than
optional features. If the core pipeline is unstable, postpone
geolocation or advanced AI work.

## Getting Started

> This section is a template until the actual framework, entry point,
> and dependencies are confirmed. Replace placeholders with tested
> commands before submission.

### Prerequisites

-   Git
-   Required Python version
-   A supported browser
-   Dependencies from `requirements.txt`
-   Optional server-side AI API key
-   Optional geolocation provider configuration

### 1. Clone the repository

``` bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd netdecoy
```

Replace the placeholder with the actual repository URL.

### 2. Create and activate a virtual environment

``` bash
python -m venv .venv
```

Windows PowerShell:

``` powershell
.\\.venv\\Scripts\\Activate.ps1
```

macOS/Linux:

``` bash
source .venv/bin/activate
```

### 3. Install dependencies

``` bash
pip install -r requirements.txt
```

### 4. Configure environment variables

If needed, configure variables using the exact names expected by the
code. These are illustrative placeholders only:

``` text
AI_API_KEY=<your-local-secret>
GEOLOCATION_API_KEY=<optional-provider-key-if-required>
```

Never commit `.env`, API keys, passwords, or secrets. Add local secret
files to `.gitignore`.

### 5. Run the application

Use the command for the framework and entry point actually implemented.
For example, a FastAPI app might use:

``` bash
uvicorn backend.app:app --reload
```

A Flask app may require a different command. Verify the import path and
startup instructions before publishing them.

### 6. Open the application

-   Health check: `http://127.0.0.1:8000/health` if implemented on that
    port.
-   API documentation: `http://127.0.0.1:8000/docs` if FastAPI is used
    and docs are enabled.
-   Dashboard: use the actual route or frontend serving command
    implemented by the project.

Do not assume these URLs work until tested.

## Demo Scenario

Use a controlled, repeatable sequence with synthetic data.

1.  **Brute-force pattern:** perform several failed login attempts;
    confirm event logging and configured detection.
2.  **Resource enumeration:** explore fake admin/API resources; confirm
    session events and scanning logic.
3.  **SQL-injection pattern:** submit harmless suspicious SQL-like text;
    confirm it is logged but never executed.
4.  **Sensitive-resource access:** interact with a synthetic backup;
    confirm event and risk signal.
5.  **Path-traversal pattern:** submit a traversal-like string; confirm
    it is recorded without reading real files.
6.  **Show intelligence:** display events, detections, risk, journey, AI
    explanation or fallback, and next-stage estimate.

### Demo message

> "NetDecoy doesn't simply wait for attackers and store logs. It turns
> their observed behavior into an evolving threat profile that helps
> defenders understand what happened and what may happen next."

Only demonstrate features that work in the submitted build. If an
optional service is unavailable, use a clearly labeled fallback.

## Testing Checklist

### Core pipeline

-   [ ] Application starts using documented commands.
-   [ ] Each trap generates a valid event.
-   [ ] Events follow the shared schema.
-   [ ] Events can be retrieved through the API.
-   [ ] Detection rules pass representative tests.
-   [ ] Risk remains between 0 and 100.
-   [ ] Repeated API reads do not accidentally increase risk.
-   [ ] Dashboard displays backend data.
-   [ ] Demo reset works if documented.

### Intelligence

-   [ ] Journey reflects recorded events.
-   [ ] AI explanation uses supplied evidence and has a fallback.
-   [ ] AI does not decide security-critical detections.
-   [ ] Estimates come from documented patterns.
-   [ ] Any displayed confidence value has a documented calculation.

### Optional services and submission

-   [ ] Geolocation failure does not break core functionality.
-   [ ] AI provider failure does not break detection or risk scoring.
-   [ ] Missing keys are handled gracefully.
-   [ ] No real credentials or sensitive data are included.
-   [ ] SQL-like inputs are never executed.
-   [ ] Traversal inputs cannot access host files.
-   [ ] Secrets are not committed.
-   [ ] README commands are tested on the demo machine.
-   [ ] Final code is pushed to GitHub.
-   [ ] Demo and fallback have been rehearsed.

## Security Boundaries

NetDecoy is a controlled prototype for demonstration and learning.

-   Keep the environment local or otherwise isolated and controlled.
-   Do not expose the decoy service publicly without appropriate
    isolation, access controls, logging, and security review.
-   Use synthetic identities, records, and decoy files.
-   Never execute submitted SQL or arbitrary commands.
-   Never resolve user-controlled traversal paths against the host
    filesystem.
-   Treat event payloads as untrusted input and validate them.
-   Do not store passwords or secrets in event payloads.
-   Keep provider keys server-side and out of source control.
-   Treat IP-derived location as approximate.
-   Treat next-stage estimation as a heuristic, not certainty.
-   Do not use AI output as the sole basis for a security-critical
    action.

## Limitations

Update this section to reflect the final implementation.

-   Detection is limited to predefined rules.
-   Thresholds may need tuning and do not cover every real-world attack.
-   Next-stage estimation depends on predefined patterns and is not
    guaranteed forecasting.
-   IP geolocation can be inaccurate or unavailable.
-   AI explanations can be imperfect and require evidence constraints
    and fallback behavior.
-   Synthetic traps are not a hardened production honeypot.
-   The prototype does not replace a production SIEM/SOC or
    incident-response platform.
-   Performance, persistence, authentication, isolation, and monitoring
    may be limited by hackathon scope.

## Future Scope

1.  Behavioral analytics using historical session data.
2.  Graph-based representation of attacker actions and resource
    relationships.
3.  Evaluated anomaly-detection models.
4.  Mapping observed behavior to MITRE ATT&CK techniques when supported
    by evidence.
5.  Stronger session correlation and event provenance.
6.  Real-time streaming and WebSocket updates.
7.  Isolated containerized decoy environments.
8.  Approved threat-intelligence integration.
9.  Analyst review of AI-generated explanations.
10. More testing, access control, audit logging, and deployment
    hardening.
11. Controlled response workflows after security review.
12. Evaluation with a documented synthetic dataset and measurable
    metrics.

## Git Workflow

Suggested branches:

``` text
main
backend
frontend
intelligence
traps
```

-   Keep `main` as the integrated, demonstrable version.
-   Work on assigned branches.
-   Coordinate changes to shared contracts.
-   Commit small, working changes throughout development.
-   Push regularly and integrate at checkpoints.
-   Test after merges and resolve conflicts with the owning member.
-   Freeze features before the final demo.

Example commit messages:

``` text
feat: initialize backend
feat: add centralized event collector
feat: create SOC dashboard
feat: implement deterministic detection rules
feat: add risk scoring
feat: add login deception page
feat: add attacker journey view
fix: handle missing geolocation response
docs: update setup and demo instructions
```

## Demo Pitch

### 30-second version

"NetDecoy is an intelligent deception and threat-intelligence prototype.
It creates a controlled fake enterprise environment, records simulated
attacker interactions, detects suspicious patterns, and calculates an
explainable risk score. It then connects observed actions into an
attacker journey, uses AI to explain the evidence, and estimates a
possible next stage using predefined behavior patterns. Our goal is to
turn isolated events into a clearer behavioral threat profile."

### Core message

**Traditional workflow:** Interaction → Logs

**NetDecoy workflow:** Interaction → Events → Detection → Risk → Journey
→ Explanation → Next-stage estimate

NetDecoy demonstrates how a controlled deception environment can make
observed activity easier to interpret and investigate.

------------------------------------------------------------------------

## Project Details

-   **Event:** IEEE SYNAPSE 2026
-   **Team name:** Add team name
-   **Team members:** Add member names and roles
-   **GitHub repository:** Add final repository URL
-   **Demo video:** Add link if created
-   **License:** Choose and add a license before public distribution
