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
    }
  ]
}
```

---

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
}
```

---

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
}
```

---

### 8. Next Stage Prediction
`GET /api/prediction`

**Response (`200 OK`)**:
```json
{
  "next_stage": "Privilege Escalation",
  "pattern_confidence": 73,
  "basis": "Based on observed attack sequence: Reconnaissance -> Credential Access -> Data Probing"
}
```

---

### 9. Demo Reset
`POST /api/reset`

**Response (`200 OK`)**:
```json
{
  "status": "success",
  "message": "Demo state successfully reset"
}
```
