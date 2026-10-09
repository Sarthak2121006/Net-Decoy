# NetDecoy API Contract & Shared Interfaces

This document defines the strict contracts between **Trap Pages (M4)**, **Event Collector & Backend APIs (M1)**, **Detection/Intelligence (M3)**, and **Dashboard (M2)**.

---

## 1. REST Endpoints (M1 Backend API)

Base URL: `http://localhost:5000` (or configured port)

### 1.1 Ingest Event
- **Endpoint**: `POST /api/events`
- **Description**: Ingests a new honeypot telemetry event from traps or clients.
- **Request Headers**: `Content-Type: application/json`
- **Request Body**:
  ```json
  {
    "session_id": "sess_demo_101",
    "source_ip": "192.168.1.50",
    "page": "login",
    "action": "failed_login",
    "event_type": "authentication",
    "payload": {
      "username": "admin",
      "password": "' OR '1'='1"
    }
  }
  ```
  *(Note: `event_id` and `timestamp` are auto-generated if omitted)*
- **Response (201 Created)**:
  ```json
  {
    "status": "success",
    "event": {
      "event_id": "evt_1712660000_a1b2c3",
      "session_id": "sess_demo_101",
      "timestamp": "2026-10-09T03:59:00.000000Z",
      "source_ip": "192.168.1.50",
      "page": "login",
      "action": "failed_login",
      "event_type": "authentication",
      "severity": "CRITICAL",
      "payload": { "username": "admin" },
      "geo": {
        "city": "Mumbai",
        "country": "India",
        "country_code": "IN",
        "latitude": 19.076,
        "longitude": 72.8777,
        "available": true
      }
    }
  }
  ```

---

### 1.2 Get Recent Events
- **Endpoint**: `GET /api/events`
- **Query Parameters**:
  - `session_id` (optional, string): Filter by specific session
  - `event_type` (optional, string): Filter by event category
  - `severity` (optional, string): Filter by severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `limit` (optional, integer, default: 50): Max items to return
- **Response (200 OK)**:
  ```json
  {
    "status": "success",
    "count": 1,
    "events": [
      {
        "event_id": "evt_1712660000_a1b2c3",
        "session_id": "sess_demo_101",
        "timestamp": "2026-10-09T03:59:00.000000Z",
        "source_ip": "192.168.1.50",
        "page": "login",
        "action": "failed_login",
        "event_type": "authentication",
        "severity": "CRITICAL",
        "payload": {},
        "geo": { "city": "Mumbai", "country": "India", "available": true }
      }
    ]
  }
  ```

---

### 1.3 System & Attack Statistics
- **Endpoint**: `GET /api/stats`
- **Description**: Returns live aggregation for dashboard KPI cards.
- **Response (200 OK)**:
  ```json
  {
    "total_events": 148,
    "total_sessions": 8,
    "threats_detected": 12,
    "high_risk": 4
  }
  ```

---

### 1.4 Risk Assessment
- **Endpoint**: `GET /api/risk`
- **Query Parameters**:
  - `session_id` (optional, string): Filter risk for a specific session (defaults to global aggregated risk).
- **Response (200 OK)**:
  ```json
  {
    "score": 87,
    "level": "HIGH",
    "breakdown": {
      "brute_force": 20,
      "scanning": 20,
      "sql_injection": 30,
      "directory_traversal": 17
    }
  }
  ```

---

### 1.5 Attacker Journey
- **Endpoint**: `GET /api/journey`
- **Query Parameters**:
  - `session_id` (optional, string)
- **Response (200 OK)**:
  ```json
  {
    "status": "success",
    "session_id": "sess_demo_101",
    "stages": [
      {
        "stage": "Reconnaissance",
        "timestamp": "2026-10-09T03:55:10Z",
        "page": "env_leak",
        "action": "read_env",
        "description": "Attacker probed environment variables trap"
      },
      {
        "stage": "Initial Access",
        "timestamp": "2026-10-09T03:56:40Z",
        "page": "login",
        "action": "sqli_probe",
        "description": "SQL injection attempt on login form"
      }
    ]
  }
  ```

---

### 1.6 AI Analysis & Intelligence Summary
- **Endpoint**: `GET /api/analysis`
- **Query Parameters**:
  - `session_id` (optional, string)
- **Response (200 OK)**:
  ```json
  {
    "status": "success",
    "analysis": "The adversary demonstrates automated reconnaissance followed by targeted SQL injection payloads against the authentication portal. Pattern correlates with credential extraction toolkits.",
    "threat_actor_profile": "Automated Scanner / Script Kiddie",
    "recommendations": [
      "Block IP subnet 192.168.1.0/24",
      "Revoke compromised session tokens",
      "Feed honeypot IOCs to upstream firewall"
    ]
  }
  ```

---

### 1.7 Next Stage Attack Prediction
- **Endpoint**: `GET /api/prediction`
- **Query Parameters**:
  - `session_id` (optional, string)
- **Response (200 OK)**:
  ```json
  {
    "next_stage": "Privilege Escalation",
    "confidence": 73,
    "basis": "Observed attack sequence pattern: Reconnaissance -> SQL Injection -> Auth Bypass"
  }
  ```

---

### 1.8 Geolocation Enrichment
- **Endpoint**: `GET /api/geo`
- **Query Parameters**:
  - `ip` (optional, string): Target IP address (defaults to requester IP or recent attacker IP)
- **Response (200 OK - Successful)**:
  ```json
  {
    "available": true,
    "ip": "192.168.1.50",
    "city": "Mumbai",
    "country": "India",
    "country_code": "IN",
    "latitude": 19.076,
    "longitude": 72.8777,
    "isp": "Local Lab Net"
  }
  ```
- **Response (200 OK - Graceful Fallback on Offline/Error)**:
  ```json
  {
    "available": false,
    "message": "Location unavailable"
  }
  ```

---

### 1.9 Reset Demo State
- **Endpoint**: `POST /api/reset`
- **Description**: Clears demo events, reset session tracking, and restores clean database state for demo repeatability.
- **Response (200 OK)**:
  ```json
  {
    "status": "success",
    "message": "Demo state reset successfully"
  }
  ```

---

## 2. Python Interfaces (M3 Intelligence & M4 Traps)

### 2.1 Central Event Logger (For Traps / M4)
```python
from backend.services.collector import log_event

event = log_event(
    session_id="sess_123",
    source_ip="127.0.0.1",
    page="login",
    action="failed_login",
    event_type="authentication",
    payload={"username": "root"}
)
```

### 2.2 Intelligence Engine Hook (For Intelligence / M3)
```python
# M3 implements or supplies analyze_events:
def analyze_events(events: list) -> dict:
    """
    Returns dictionary with:
      - risk: { score: int, level: str, breakdown: dict }
      - prediction: { next_stage: str, confidence: int, basis: str }
      - analysis: { summary: str, threat_actor_profile: str, recommendations: list }
      - journey: list of stages
    """
    pass
```
