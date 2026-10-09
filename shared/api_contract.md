<<<<<<< HEAD
# NetDecoy API Contract & Intelligence Specifications

This document outlines the contracts and schemas connecting the Deception Traps, Event Collector, Detection & Risk Engines, AI Explanation, Next-Stage Estimation, and the SOC Dashboard.

---

## 1. Event Ingestion (`POST /api/events`)

Each deception trap emits interactions conforming to `shared/event_schema.json`.

### Request Body
```json
{
  "event_id": "evt_001",
  "session_id": "sess_001",
  "timestamp": "2026-10-08T14:30:21Z",
  "source_ip": "192.168.1.105",
  "page": "login",
  "action": "failed_login",
  "event_type": "authentication",
  "payload": {
    "username": "admin"
  }
}
```

### Ingestion Response (`201 Created`)
```json
{
  "status": "success",
  "event_id": "evt_001",
  "detections": [
    {
      "attack_type": "BRUTE_FORCE",
      "detected": true,
      "severity": "HIGH",
      "evidence": [
        "5 failed login attempts observed within 60 seconds"
      ]
=======
# NetDecoy API Contract & Integration Specifications

This document defines the REST API contract between the **NetDecoy Backend (M1)**, **SOC Dashboard Frontend (M2)**, and **Intelligence Engine (M3)**.

---

## Base Configuration

- **Default Base URL**: `http://127.0.0.1:8000`
- **Content-Type**: `application/json`
- **Polling Interval**: Recommended 2 seconds (`2000ms`)

---

## Core Endpoints

### 1. System Health
`GET /health`

**Response (`200 OK`)**:
```json
{
  "status": "ok",
  "timestamp": "2026-10-09T09:30:00Z",
  "version": "1.0.0"
}
```

---

### 2. Dashboard Statistics
`GET /api/stats`

**Response (`200 OK`)**:
```json
{
  "total_events": 142,
  "threats_detected": 38,
  "high_risk_sessions": 4,
  "active_sessions": 6
}
```

---

### 3. Live Event Feed
`GET /api/events?limit=50`

**Response (`200 OK`)**:
```json
[
  {
    "event_id": "evt_1092",
    "session_id": "sess_8832",
    "timestamp": "2026-10-09T09:31:04Z",
    "page": "login",
    "action": "failed_login",
    "event_type": "authentication",
    "severity": "HIGH",
    "source_ip": "185.220.101.5",
    "payload": {
      "username": "admin",
      "attempt": 4
    }
  }
]
```

---

### 4. Risk Score & Breakdown
`GET /api/risk`

**Response (`200 OK`)**:
```json
{
  "score": 87,
  "severity_label": "CRITICAL",
  "breakdown": [
    { "signal": "Brute Force Pattern", "points": 20 },
    { "signal": "Endpoint Scanning", "points": 20 },
    { "signal": "SQL Injection Pattern", "points": 30 },
    { "signal": "Sensitive Resource Access", "points": 17 }
  ]
}
```

*Severity Bands*:
- `0 - 29`: `LOW`
- `30 - 59`: `MEDIUM`
- `60 - 79`: `HIGH`
- `80 - 100`: `CRITICAL`

---

### 5. Attacker Journey
`GET /api/journey`

**Response (`200 OK`)**:
```json
{
  "session_id": "sess_8832",
  "nodes": [
    {
      "step": 1,
      "page": "login",
      "action": "Failed Login Attempt",
      "timestamp": "09:31:04",
      "status": "warning"
    },
    {
      "step": 2,
      "page": "admin",
      "action": "Resource Enumeration",
      "timestamp": "09:31:08",
      "status": "warning"
    },
    {
      "step": 3,
      "page": "database",
      "action": "SQL Injection Pattern Detected",
      "timestamp": "09:31:13",
      "status": "critical"
    },
    {
      "step": 4,
      "page": "backup",
      "action": "Decoy Backup File Accessed",
      "timestamp": "09:31:18",
      "status": "critical"
    },
    {
      "step": 5,
      "page": "api",
      "action": "Internal API Endpoint Probe",
      "timestamp": "09:31:25",
      "status": "critical"
>>>>>>> upstream/frontend-development
    }
  ]
}
```

---

<<<<<<< HEAD
## 2. Risk Score & Breakdown (`GET /api/risk`)

Calculated deterministically by `risk_engine.py` and `intelligence_bridge.py`. Strictly bounded between `0` and `100`.

### Response
```json
{
  "score": 100,
  "level": "CRITICAL",
  "breakdown": {
    "brute_force": 20,
    "scanning": 20,
    "sql_injection": 30,
    "sensitive_access": 20,
    "path_traversal": 30,
    "repeated_suspicious": 10
  },
  "capped": true,
  "signals": [
    {
      "signal": "Brute Force",
      "attack_type": "BRUTE_FORCE",
      "points": 20,
      "severity": "HIGH",
      "evidence": [
        "5 failed login attempts observed in session"
      ]
    }
  ],
  "session_id": "sess_001"
=======
### 6. Geolocation Data
`GET /api/geo`

**Response (`200 OK`)**:
```json
{
  "ip": "185.220.101.5",
  "city": "Frankfurt",
  "country": "Germany",
  "country_code": "DE",
  "latitude": 50.1109,
  "longitude": 8.6821,
  "status": "available"
}
```

*Fallback when offline*:
```json
{
  "status": "unavailable",
  "message": "Location unavailable"
>>>>>>> upstream/frontend-development
}
```

---

<<<<<<< HEAD
## 3. Attacker Journey (`GET /api/journey`)

Constructed chronologically mapping raw interactions into observed stages.

### Response
```json
{
  "current_stage": "DATA_ACCESS",
  "stages_visited": [
    "RECONNAISSANCE",
    "CREDENTIAL_ACCESS",
    "RESOURCE_DISCOVERY",
    "PRIVILEGE_ESCALATION",
    "DATA_ACCESS"
  ],
  "stage_count": 5,
  "timeline": [
    {
      "step": 1,
      "event_id": "evt_demo_001",
      "timestamp": "2026-10-08T14:30:00Z",
      "page": "login",
      "action": "page_view",
      "stage": "RECONNAISSANCE",
      "detail": "Authentication attempt on login decoy"
    }
  ],
  "total_steps": 11,
  "session_id": "sess_001"
}
```

---

## 4. AI Threat Analysis (`GET /api/analysis`)

Evidence summary, likely intent, and investigation recommendations generated by `ai_engine.py`.

### Response
```json
{
  "summary": "Session sess_001 triggered multiple suspicious pattern detections.",
  "likely_intent": "Observed activity suggests a phased intrusion effort targeting credentials and sensitive assets.",
  "evidence": [
    "5 failed login attempts observed in session"
  ],
  "recommended_actions": [
    "Flag session sess_001 in SOC monitoring console for ongoing correlation"
  ],
  "session_id": "sess_001",
  "is_fallback": true
=======
### 7. AI Threat Analysis
`GET /api/analysis`

**Response (`200 OK`)**:
```json
{
  "summary": "The attacker appears to have moved from initial reconnaissance toward credential probing and sensitive decoy resource exploitation.",
  "evidence": [
    "Multiple failed authentication attempts detected on corporate login trap",
    "Administrative endpoint probing within a short 10-second window",
    "SQL-like injection payload submitted to synthetic database console",
    "Access attempt logged on synthetic backup archive"
  ],
  "intent": "Credential Harvesting & Sensitive Data Exfiltration Attempt",
  "recommendations": [
    "Block source IP 185.220.101.5 at edge firewall",
    "Invalidate active session tokens associated with sess_8832",
    "Audit adjacent corporate directory access logs"
  ]
>>>>>>> upstream/frontend-development
}
```

---

<<<<<<< HEAD
## 5. Next-Stage Estimation (`GET /api/prediction`)

Pattern-based estimation of the attacker's next anticipated attack stage.

### Response
```json
{
  "current_stage": "DATA_ACCESS",
  "next_stage": "EXFILTRATION",
  "confidence": 85,
  "confidence_label": "Pattern confidence",
  "basis": "Observed sequence matches known attack-stage pattern (DATA_ACCESS -> EXFILTRATION)",
  "potential_targets": [
    "backup",
    "api"
  ],
  "alternative_stages": [
    {
      "stage": "PERSISTENCE",
      "confidence": 15
    }
  ],
  "session_id": "sess_001"
=======
### 8. Next Stage Prediction
`GET /api/prediction`

**Response (`200 OK`)**:
```json
{
  "next_stage": "Privilege Escalation",
  "pattern_confidence": 73,
  "basis": "Based on observed attack sequence: Reconnaissance -> Credential Access -> Data Probing"
>>>>>>> upstream/frontend-development
}
```

---

<<<<<<< HEAD
## 6. Unified Session Analysis (`POST /api/analyze`)

Comprehensive session snapshot combining all engines.

### Response
```json
{
  "session_id": "sess_001",
  "event_count": 11,
  "detections": [],
  "detected_attack_types": [],
  "risk": {},
  "journey": {},
  "prediction": {},
  "ai_analysis": {},
  "processed_at": "2026-10-08T14:35:00Z"
}
```

---

## 7. Additional Backend SOC Endpoints

- `GET /api/stats` — Overall KPI metrics (`total_events`, `total_sessions`, `threats_detected`, `high_risk`)
- `GET /api/events` — Query recent events with filters
- `GET /api/alerts` — Real-time SOC incident alerts
- `GET /api/sessions` — Active sessions list & deep-dive audits
- `GET /api/geo` — Geolocation info with graceful fallback
- `GET / POST / DELETE /api/quarantine` — Active defense IP blocking
- `POST /api/reset` — Clean database reset for repeat demonstrations
=======
### 9. Demo Reset
`POST /api/reset`

**Response (`200 OK`)**:
```json
{
  "status": "success",
  "message": "Demo state successfully reset"
}
```
>>>>>>> upstream/frontend-development
