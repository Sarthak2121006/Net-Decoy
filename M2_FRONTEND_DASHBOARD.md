# NetDecoy --- M2 Frontend & SOC Dashboard Engineer

## Role

You are **M2 --- Frontend and SOC Dashboard Lead**.

Your responsibility is to turn backend/security data into a
professional, fast-to-understand SOC dashboard.

The dashboard is the main visual surface judges will see.

------------------------------------------------------------------------

# 1. Critical Rules

1.  Work primarily on the `frontend` branch.
2.  Do not modify backend logic.
3.  Consume APIs according to `shared/api_contract.md`.
4.  Do not hard-code fake security statistics into the final dashboard.
5.  Keep the dashboard to one primary page.
6.  Prioritize clarity over excessive animations.
7.  The dashboard must still work if AI or geolocation temporarily
    fails.
8.  Never make external services a single point of failure.

------------------------------------------------------------------------

# 2. Dashboard Goal

The judge should understand the entire system in approximately 10
seconds.

They should see:

``` text
Threats
Risk
Live activity
Attack origin
Attack journey
AI explanation
Next likely stage
```

------------------------------------------------------------------------

# 3. Suggested Structure

``` text
frontend/
├── dashboard.html
├── dashboard.css
├── dashboard.js
└── components/
```

Use the team's selected frontend technology if already agreed.

Do not introduce a complex framework if plain HTML/CSS/JS is sufficient.

------------------------------------------------------------------------

# 4. Main Dashboard Layout

Build:

``` text
┌──────────────────────────────────────────────┐
│ 🛡️ NETDECOY — SECURITY OPERATIONS CENTER   │
├─────────┬─────────┬─────────┬────────────────┤
│ Events  │ Threats │ High Risk│ Sessions      │
├─────────┴─────────┴─────────┴────────────────┤
│ LIVE EVENT FEED                               │
├──────────────────────┬───────────────────────┤
│ RISK SCORE           │ ATTACK ORIGIN MAP     │
├──────────────────────┴───────────────────────┤
│ ATTACKER JOURNEY                              │
├──────────────────────────────────────────────┤
│ AI THREAT ANALYSIS                            │
├──────────────────────────────────────────────┤
│ NEXT LIKELY ATTACK STAGE                      │
└──────────────────────────────────────────────┘
```

------------------------------------------------------------------------

# 5. Stats Cards

Display:

``` text
Total Events
Threats Detected
High Risk
Active Sessions
```

Data source:

``` text
GET /api/stats
```

Do not calculate these independently in frontend if backend already
provides them.

------------------------------------------------------------------------

# 6. Live Event Feed

Poll or refresh the API at a reasonable interval.

Example:

``` text
14:31:04  LOGIN      Failed authentication
14:31:08  SCAN       Multiple endpoints probed
14:31:13  DATABASE   Suspicious query
14:31:18  BACKUP     Sensitive file accessed
```

Each event should visually indicate:

-   timestamp
-   page
-   action
-   event type
-   severity if available

Do not make the feed too tall.

------------------------------------------------------------------------

# 7. Risk Score

Display:

``` text
RISK SCORE

87 / 100
HIGH
```

Add a simple visual progress indicator.

Use:

``` text
0–29     LOW
30–59    MEDIUM
60–79    HIGH
80–100   CRITICAL
```

Use the same thresholds as M3.

Never invent your own thresholds.

------------------------------------------------------------------------

# 8. Risk Breakdown

If available, show:

``` text
Brute Force        +20
Scanning           +20
SQL Injection      +30
Sensitive Access   +20
```

This helps judges understand that the score is explainable.

------------------------------------------------------------------------

# 9. Geolocation Map

Use Leaflet or the team's chosen map library.

Show approximate attacker location.

Example:

``` text
        🌍
     ●
  attacker
```

Display:

-   city
-   country
-   approximate coordinates

If location is unavailable:

``` text
Location unavailable
```

Do not break the rest of the dashboard.

------------------------------------------------------------------------

# 10. Attack Journey

This is one of the most important visual features.

Example:

``` text
LOGIN
  ●
  │
ADMIN
  ●
  │
DATABASE
  ●
  │
BACKUP
  ●
  │
API
```

It should show chronological attacker movement.

Use:

``` text
GET /api/journey
```

------------------------------------------------------------------------

# 11. AI Threat Analysis

Display a dedicated card:

``` text
🧠 AI THREAT ANALYSIS

The attacker appears to have moved from
reconnaissance toward credential access.

Evidence:
• Multiple failed logins
• Endpoint probing
• Administrative resources accessed
```

Use:

``` text
GET /api/analysis
```

Do not call the LLM directly from frontend.

Frontend → backend → AI engine.

------------------------------------------------------------------------

# 12. Prediction

Display:

``` text
🔮 NEXT LIKELY STAGE

Privilege Escalation

Pattern Confidence: 73%

Based on the observed attack sequence.
```

Use:

``` text
GET /api/prediction
```

Do not present the prediction as certainty.

Use language like:

-   likely
-   estimated
-   pattern confidence

------------------------------------------------------------------------

# 13. Dashboard Refresh Strategy

Keep it simple.

For hackathon:

``` text
fetch every 2 seconds
```

is acceptable if the backend is lightweight.

Do not build WebSockets unless the team already has them working
reliably.

Polling is safer for six hours.

------------------------------------------------------------------------

# 14. Demo Mode

Create a clear reset button if the backend supports:

``` text
POST /api/reset
```

The team should be able to reset the dashboard before the judge arrives.

Optional:

``` text
Demo Reset
```

Keep it hidden from normal presentation if it looks cleaner.

------------------------------------------------------------------------

# 15. Antigravity Prompt

Use:

> You are working only on the NetDecoy frontend branch. Inspect the
> repository and read `shared/api_contract.md` before modifying
> anything. Build or improve the SOC dashboard using the existing
> backend APIs. Do not modify backend or intelligence logic. Handle API
> failures gracefully and show useful fallback states. After
> implementation, run the frontend and verify the dashboard with the
> available browser/testing MCP tools.

------------------------------------------------------------------------

# 16. MCP Usage

Use browser MCP if available to:

-   open dashboard
-   verify responsive layout
-   perform demo interaction
-   inspect browser errors
-   verify map rendering
-   verify API data appears correctly

Use Git MCP if available to:

-   inspect branch
-   review changed files
-   commit logically grouped changes

Do not use MCP to rewrite unrelated branches.

------------------------------------------------------------------------

# 17. Timeline

## 0:20--1:30

Build:

-   dashboard skeleton
-   header
-   stats cards
-   event feed

Use temporary mock data ONLY for UI development.

## 1:30 checkpoint

Prepare the dashboard to consume real backend APIs.

## 1:30--2:45

Build:

-   risk
-   filters
-   event severity
-   API integration

## 2:45 checkpoint

Dashboard displays real MVP data.

## 2:45--4:00

Build:

-   map
-   journey
-   AI analysis
-   prediction

## 4:00 checkpoint

Complete visual dashboard.

## 4:00--5:00

Browser testing and visual polish.

## 5:00--5:30

Screenshots for README.

## 5:30--6:00

No new UI features.

------------------------------------------------------------------------

# 18. Acceptance Criteria

-   [ ] Dashboard loads reliably
-   [ ] Stats are real
-   [ ] Live events appear
-   [ ] Risk score updates
-   [ ] Map renders
-   [ ] Journey renders
-   [ ] AI explanation renders
-   [ ] Prediction renders
-   [ ] API failure states don't crash UI
-   [ ] Dashboard works after reset
-   [ ] No console-breaking errors
-   [ ] Demo flow is visually obvious

------------------------------------------------------------------------

# 19. Commit Examples

``` text
feat: create SOC dashboard
feat: add statistics cards
feat: add live event feed
feat: add risk visualization
feat: integrate attacker map
feat: add attack journey
feat: add AI analysis panel
feat: add prediction panel
fix: handle missing geo data
fix: handle API loading states
```

------------------------------------------------------------------------

# 20. Final Responsibility

Your job is not to make the dashboard contain every possible metric.

Your job is:

**Make the judge understand the intelligence of NetDecoy immediately.**
