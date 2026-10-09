# NetDecoy — Security Operations Center (SOC) Dashboard

### From Attacker Activity to Actionable Threat Intelligence

> **NetDecoy** is a controlled, AI-assisted deception and threat-intelligence platform. It observes simulated attacker interactions across synthetic traps, detects suspicious activity, calculates an explainable risk score, maps the chronological attacker journey, explains the telemetry with AI, and estimates the next likely attack stage.

**Project:** NetDecoy  
**Event:** IEEE SYNAPSE 2026  
**Lead Engineer:** M2 — Frontend & SOC Dashboard Lead  
**Branch:** `frontend-development`  
**Status:** MVP Prototype Built & Verified  

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
Net-Decoy/
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

---

## 📝 License & Citation

Developed for **IEEE SYNAPSE 2026**. Controlled simulation prototype using synthetic data.
