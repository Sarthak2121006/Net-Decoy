# NetDecoy — Security Operations Center (SOC) Dashboard

### From Attacker Activity to Actionable Threat Intelligence

> **NetDecoy** is a controlled, AI-assisted deception and threat-intelligence platform. It observes simulated attacker interactions across synthetic traps, detects suspicious activity, calculates an explainable risk score, maps the chronological attacker journey, explains the telemetry with AI, and estimates the next likely attack stage.

<<<<<<< HEAD
**Project:** NetDecoy\
**Event:** IEEE SYNAPSE 2026\
**Status:** In Active Development / Integration (M1 Backend, M3 Intelligence, and M4 Traps)\
**Safety model:** Controlled simulation using synthetic resources and
data.
=======
**Project:** NetDecoy  
**Event:** IEEE SYNAPSE 2026  
**Lead Engineer:** M2 — Frontend & SOC Dashboard Lead  
**Branch:** `frontend-development`  
**Status:** MVP Prototype Built & Verified  
>>>>>>> upstream/frontend-development

---

## 🛡️ Executive Overview & SOC Dashboard

The SOC Dashboard is the primary visual operations center for NetDecoy. Designed for rapid threat comprehension, it provides security analysts and presentation judges with an immediate, high-level operational picture within 10 seconds of observation.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ NETDECOY — SECURITY OPERATIONS CENTER (SOC)                            │
├───────────────┬───────────────────┬─────────────────────┬───────────────────┤
│ Total Events  │ Threats Detected  │ High Risk Sessions  │ Active Sessions   │
│ 148           │ 42                │ 3                   │ 5                 │
├───────────────┴───────────────────┴─────────────────────┴───────────────────┤
│ LIVE EVENT FEED                                                             │
│ 14:31:04  /login     Failed Authentication                HIGH    185.220.101.5 │
│ 14:31:08  /admin     Endpoint Enumeration Probed          MEDIUM  185.220.101.5 │
│ 14:31:13  /database  SQL-Like Input Detected              CRITICAL 185.220.101.5│
├──────────────────────────────────────┬──────────────────────────────────────┤
│ THREAT RISK ASSESSMENT               │ ATTACKER ORIGIN GEOLOCATION MAP      │
│ Score: 87 / 100 [CRITICAL]           │ Frankfurt, Germany (50.1109, 8.6821) │
│ Breakdown: Brute Force (+20), SQLi(+30)│ Interactive Dark Leaflet Map Pin    │
├──────────────────────────────────────┴──────────────────────────────────────┤
│ ATTACKER CHRONOLOGICAL JOURNEY MAP                                          │
│ [LOGIN] ➔ [ADMIN] ➔ [DATABASE] ➔ [BACKUP] ➔ [API]                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ 🧠 AI THREAT ANALYSIS ENGINE                                                 │
│ Executive Summary: Attacker session sess_8832 initiated credential brute... │
│ Evidence: Multiple failed logins, admin scanning, SQL injection payload     │
│ Containment: Block IP 185.220.101.5, revoke session sess_8832                │
├─────────────────────────────────────────────────────────────────────────────┤
│ 🔮 NEXT LIKELY ATTACK STAGE                                                 │
│ Estimated Next Phase: PRIVILEGE ESCALATION (Pattern Confidence: 78%)        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Dashboard Features

1. **Top Metrics Cards**: Real-time counters for Total Events, Threats Detected, High Risk Sessions, and Active Sessions (`GET /api/stats`).
2. **Live Event Feed Table**: Filtering by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), showing ISO timestamps, trap routes, actions, and source IPs (`GET /api/events`).
3. **Bounded Threat Risk Gauge**: 0–100 risk score meter with dynamic severity status bands (LOW: 0–29, MEDIUM: 30–59, HIGH: 60–79, CRITICAL: 80–100) and explicit points breakdown list (`GET /api/risk`).
4. **Interactive Leaflet Geolocation Map**: Plots approximate attacker origin using dark CartoDB tiles and custom glowing map markers (`GET /api/geo`). Includes automatic fallback if IP geolocation is unavailable.
5. **Attacker Chronological Journey Map**: Visual step-by-step node flow connecting attacker movement across traps (`GET /api/journey`).
6. **AI Threat Analysis Panel**: Dedicated card displaying LLM-synthesized executive threat summary, structured telemetry evidence bullets, and recommended containment actions (`GET /api/analysis`).
7. **Next Stage Prediction Card**: Pattern-based estimate of future attacker trajectory with pattern confidence bar (`GET /api/prediction`).
8. **Judge Demo Simulator & Reset**: Built-in standalone demo sequence controls (`Brute-Force`, `Scan`, `SQLi`, `Full Attack Chain`) and state reset (`POST /api/reset`).

---

## 🛠️ Architecture & Data Flow

``` mermaid
flowchart TD
    Attacker[Simulated Attacker] --> Traps[Deception Traps /login, /admin, /database, /backup]
    Traps --> Collector[Central Event Collector]
    Collector --> Storage[(Event Database)]
    Storage --> Detection[Detection & Risk Engine]
    Detection --> Journey[Attacker Journey Engine]
    Detection --> AI[AI Threat Analysis]
    Detection --> Predict[Next Stage Estimator]
    
    Storage --> API[Backend REST API]
    Detection --> API
    Journey --> API
    AI --> API
    Predict --> API

    API --> Dashboard[SOC Dashboard frontend/dashboard.html]
```

---

## 📁 Repository Structure

``` text
<<<<<<< HEAD
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
and documents how it is calculated. Pattern confidence comes from a predefined transition table plus a depth heuristic, not a trained model. Do not invent percentages or
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
=======
Net-Decoy/
>>>>>>> upstream/frontend-development
├── frontend/
│   ├── dashboard.html      # Main SOC Dashboard layout & markup
│   ├── dashboard.css       # Dark cyber aesthetic styling & glassmorphism
│   └── dashboard.js        # REST API polling & standalone simulation engine
├── shared/
│   ├── api_contract.md     # Unified API specification contract
│   └── event_schema.json   # Event payload schema
├── M2_FRONTEND_DASHBOARD.md # M2 Lead Role specification
└── README.md               # Main project documentation
```

---

## 🔌 API Integration Reference

The SOC Dashboard consumes the following backend routes:

| Method | Endpoint | Purpose |
| :--- | :--- | :--- |
| `GET` | `/health` | Backend status check |
| `GET` | `/api/stats` | Summary metric counts |
| `GET` | `/api/events` | Recent event logs |
| `GET` | `/api/risk` | Bounded risk score & breakdown |
| `GET` | `/api/journey` | Step-by-step attacker journey |
| `GET` | `/api/geo` | IP geolocation coordinates |
| `GET` | `/api/analysis` | AI threat explanation |
| `GET` | `/api/prediction` | Next likely attack stage |
| `POST` | `/api/reset` | Reset demo session state |

*Note: If the backend REST API is offline or not yet initialized, `dashboard.js` automatically activates its standalone simulation engine so the dashboard remains 100% functional for offline demos.*

---

## 💻 Getting Started

<<<<<<< HEAD
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
## Getting Started

### Prerequisites

- Git
- Python 3.10+
- Dependencies from `requirements.txt`

### 1. Clone the repository

```bash
git clone https://github.com/Sarthak2121006/Net-Decoy.git
cd Net-Decoy
```

### 2. Create and activate a virtual environment

Windows PowerShell:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```
=======
### 1. Clone & Switch to Frontend Branch
```bash
git clone https://github.com/Sarthak2121006/Net-Decoy.git
cd Net-Decoy
git checkout frontend-development
```

### 2. View Dashboard Locally
Simply open `frontend/dashboard.html` in any modern web browser, or serve it using Python:

```bash
python -m http.server 8080
```

Then visit: `http://localhost:8080/frontend/dashboard.html`

---

## 👥 Role Responsibilities (M2 Lead)

- **Owner**: M2 — Frontend & SOC Dashboard Lead
- **Scope**: Single-page SOC Dashboard UI (`frontend/`), aesthetic theme, Leaflet map integration, API consumption, failure tolerance, judge demo simulator.
- **Branch**: `frontend-development`
>>>>>>> upstream/frontend-development

---

<<<<<<< HEAD
```bash
pip install -r requirements.txt
```

### 4. Run the Backend Server

```bash
python backend/app.py
```
*The backend runs on `http://localhost:5000` with CORS enabled across all origins for dashboard and trap integration.*

### 5. Run the Automated Test Suite

```bash
python -m pytest tests/ -v
```

### 6. Verify Core API Endpoints

- **Health check**: `http://localhost:5000/api/health`
- **Recent events**: `http://localhost:5000/api/events`
- **Dashboard Stats**: `http://localhost:5000/api/stats`
- **Risk Assessment**: `http://localhost:5000/api/risk`
- **Attacker Journey**: `http://localhost:5000/api/journey`
- **AI Threat Analysis**: `http://localhost:5000/api/analysis`
- **Next Stage Prediction**: `http://localhost:5000/api/prediction`
- **IP Geolocation**: `http://localhost:5000/api/geo`
- **Reset Demo State**: `POST http://localhost:5000/api/reset`

### 7. Emitting Events from Trap Pages (M4)

```python
from traps.collector_client import TrapCollectorClient

client = TrapCollectorClient(backend_url="http://localhost:5000", trap_name="login_trap")
client.emit_event(
    session_id="sess_demo_01",
    source_ip="192.168.1.15",
    action="failed_login",
    event_type="authentication",
    payload={"username": "admin", "password": "' OR 1=1 --"}
)
```

### 8. Run the Attack Simulation Demo

```bash
python scripts/simulate_attack.py
```
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

- **Event:** IEEE SYNAPSE 2026
- **Team name:** core-innovators
- **Team members:** Sarthak Gaikwad, Chaitanya Sarkate, Vishvjeet Kamble, Ajit Bhandekar
- **GitHub repository:** [https://github.com/Sarthak2121006/Net-Decoy](https://github.com/Sarthak2121006/Net-Decoy)
- **Demo video:** Add link if created
- **License:** MIT License

