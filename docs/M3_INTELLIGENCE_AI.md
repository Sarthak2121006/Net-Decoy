# NetDecoy --- M3 Threat Intelligence & AI Engineer

## Role

You are **M3 --- Intelligence, Detection, Risk, AI and Prediction
Lead**.

This is the technical intelligence core of NetDecoy.

You own:

``` text
Rule-based detection
Risk scoring
Attack classification
Attack journey logic
AI explanation
Next-stage prediction
```

------------------------------------------------------------------------

# 1. Critical Rules

1.  Work primarily on the `intelligence` branch.
2.  Read `shared/event_schema.json` before coding.
3.  Do not modify trap UI or dashboard implementation.
4.  Detection must be deterministic and explainable.
5.  Do not let the LLM be the sole security decision-maker.
6.  Do not invent confidence percentages.
7.  AI must have fallback behavior.
8.  Never expose real credentials or real sensitive data.
9.  Keep the intelligence engine fast enough for a live demo.
10. Prefer simple reliable logic over complicated ML.

------------------------------------------------------------------------

# 2. Intelligence Pipeline

Your complete pipeline:

``` text
Events
  ↓
Normalize
  ↓
Detect
  ↓
Risk
  ↓
Attack Stage
  ↓
Journey
  ↓
AI Explanation
  ↓
Next-stage Prediction
```

------------------------------------------------------------------------

# 3. Rule-Based Attack Detection

Implement:

## Brute Force

Trigger when repeated failed login events occur in a session/window.

Example:

``` text
5 failed login attempts
→ BRUTE_FORCE
```

------------------------------------------------------------------------

## Scanning

Trigger when a session probes multiple different pages/endpoints
rapidly.

Example:

``` text
/login
/admin
/api
/backup
/database
```

→ SCANNING

------------------------------------------------------------------------

## SQL Injection

Detect controlled suspicious query patterns.

Do not execute the malicious query.

The system only identifies the pattern.

Example categories:

``` text
union select
OR-based authentication bypass patterns
comment-based SQL patterns
```

------------------------------------------------------------------------

## Path Traversal

Detect controlled traversal indicators such as:

``` text
../
..\
encoded traversal patterns
```

Never actually access the host filesystem.

------------------------------------------------------------------------

# 4. Detection Output

Every detection should return something similar to:

``` json
{
  "attack_type": "SQL_INJECTION",
  "detected": true,
  "severity": "HIGH",
  "evidence": [
    "Suspicious query pattern"
  ]
}
```

------------------------------------------------------------------------

# 5. Risk Engine

Create:

``` text
risk_engine.py
```

Risk score:

``` text
0–100
```

Suggested starting weights:

``` text
Brute Force          +20
Scanning             +20
SQL Injection        +30
Path Traversal       +30
Sensitive Access     +20
Repeated Suspicious   +10
```

Cap:

``` text
min(score, 100)
```

Levels:

``` text
0–29     LOW
30–59    MEDIUM
60–79    HIGH
80–100   CRITICAL
```

Make weights easy to modify.

------------------------------------------------------------------------

# 6. Risk Breakdown

Return:

``` json
{
  "score": 87,
  "level": "HIGH",
  "breakdown": {
    "brute_force": 20,
    "scanning": 20,
    "sql_injection": 30,
    "sensitive_access": 17
  }
}
```

This makes the system explainable.

------------------------------------------------------------------------

# 7. Attack Journey

Convert events into stages.

Suggested stages:

``` text
RECONNAISSANCE
       ↓
SCANNING
       ↓
CREDENTIAL_ACCESS
       ↓
RESOURCE_DISCOVERY
       ↓
PRIVILEGE_ESCALATION
       ↓
DATA_ACCESS
```

Do not require every attack to follow every stage.

The journey should be based on observed evidence.

Example:

``` text
Login failures
→ Credential Access

Multiple endpoint probes
→ Reconnaissance / Scanning

Admin access
→ Resource Discovery

Sensitive backup access
→ Data Access
```

------------------------------------------------------------------------

# 8. AI Explanation

Create:

``` text
ai_engine.py
```

The AI receives structured evidence.

Example:

``` json
{
  "session_id": "sess_123",
  "risk_score": 82,
  "detected_attacks": [
    "BRUTE_FORCE",
    "SCANNING"
  ],
  "events": [...]
}
```

Ask the model to produce:

``` text
1. Attack summary
2. Likely intent
3. Evidence
4. Recommended defensive action
```

Keep the output concise.

------------------------------------------------------------------------

# 9. AI Prompt Principles

The AI should be told:

-   You are a cybersecurity analyst.
-   Analyze only supplied evidence.
-   Do not invent events.
-   Do not claim certainty.
-   Clearly distinguish observed behavior from inference.
-   Do not provide offensive instructions.
-   Return structured analysis.

Example output:

``` json
{
  "summary": "...",
  "likely_intent": "...",
  "evidence": ["...", "..."],
  "recommended_actions": ["...", "..."]
}
```

------------------------------------------------------------------------

# 10. AI Fallback

The project must work even if the AI API fails.

Implement fallback:

``` text
AI available
→ generated explanation

AI unavailable
→ deterministic template explanation
```

Example fallback:

> "Multiple authentication failures and endpoint probes were observed.
> The session is classified as high risk based on the configured
> detection rules."

Never allow:

``` text
AI API failure
→ dashboard crash
```

------------------------------------------------------------------------

# 11. Next-Stage Prediction

This is the signature feature.

Do NOT ask an LLM:

> "Give me a probability."

Instead use a controlled sequence model/rule engine.

Example transitions:

``` text
RECONNAISSANCE
→ SCANNING

SCANNING
→ CREDENTIAL_ACCESS

CREDENTIAL_ACCESS
→ PRIVILEGE_ESCALATION

PRIVILEGE_ESCALATION
→ DATA_ACCESS
```

You can assign pattern confidence based on predefined/synthetic
historical sequences.

Example:

``` text
Credential Access
→ Privilege Escalation

Pattern confidence = 73%
```

The UI should say:

**Pattern confidence**, not guaranteed probability.

------------------------------------------------------------------------

# 12. Prediction Output

``` json
{
  "next_stage": "PRIVILEGE_ESCALATION",
  "confidence": 73,
  "basis": "Observed sequence matches known attack-stage pattern"
}
```

------------------------------------------------------------------------

# 13. Important Q&A Defense

If judges ask:

> "Is this actually predicting the future?"

Answer:

> "No system can guarantee an attacker's next action. Our prototype
> performs pattern-based next-stage estimation from the observed attack
> sequence. The confidence represents similarity to predefined attack
> progression patterns."

This is technically honest and defensible.

------------------------------------------------------------------------

# 14. Antigravity Prompt

Use:

> You are working only on the NetDecoy intelligence branch. Read
> `shared/event_schema.json` and `shared/attack_types.json` first.
> Implement deterministic attack detection, explainable risk scoring,
> attack journey generation, AI threat explanation, and pattern-based
> next-stage prediction. Do not modify frontend or trap files. Do not
> let the LLM make security-critical detection decisions. Include
> fallback behavior when the AI service is unavailable. Run tests for
> every detection rule.

------------------------------------------------------------------------

# 15. MCP Usage

Use MCP for:

-   repository inspection
-   running tests
-   checking application behavior
-   API testing
-   documentation lookup
-   inspecting logs

If browser MCP exists, generate a controlled attack sequence and verify
that:

``` text
trap → event → detection → risk → dashboard
```

works.

------------------------------------------------------------------------

# 16. Timeline

## 0:20--1:30

Build:

-   detection framework
-   brute force
-   scanning
-   SQL injection
-   path traversal
-   risk scoring

## 1:30 checkpoint

Verify synthetic events produce correct detections.

## 1:30--2:45

Build:

-   remaining detection rules
-   attack-stage mapping
-   journey engine

## 2:45 checkpoint

MVP intelligence complete.

## 2:45--4:00

Build:

-   AI explanation
-   prediction
-   fallback

## 4:00 checkpoint

Full intelligence pipeline works.

## 4:00--5:00

Tune:

-   weights
-   prompts
-   edge cases
-   timeouts
-   output format

## 5:00--6:00

Integration and demo testing.

------------------------------------------------------------------------

# 17. Acceptance Criteria

-   [ ] Brute force detection works
-   [ ] Scanning detection works
-   [ ] SQL injection pattern detection works
-   [ ] Path traversal detection works
-   [ ] Risk score always 0--100
-   [ ] Risk breakdown is explainable
-   [ ] Attack journey is generated
-   [ ] AI explanation works
-   [ ] AI fallback works
-   [ ] Prediction works
-   [ ] Confidence is defensible
-   [ ] No offensive action is executed
-   [ ] Backend can consume intelligence output

------------------------------------------------------------------------

# 18. Commit Examples

``` text
feat: add detection engine
feat: add brute force detector
feat: add scanning detector
feat: add sql injection detector
feat: add path traversal detector
feat: add risk scoring
feat: add attack journey
feat: add AI threat analysis
feat: add prediction engine
fix: add AI fallback
fix: stabilize prediction confidence
```

------------------------------------------------------------------------

# 19. Final Responsibility

Your objective is:

**Turn raw attacker behavior into understandable security
intelligence.**

The winning technical story is:

**Rules detect → risk quantifies → AI explains → sequence model
predicts.**
