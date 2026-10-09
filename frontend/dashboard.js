/**
 * NetDecoy — SOC Dashboard JavaScript Engine (Clean Light Theme)
 * Integrated with IPInfo Geolocation API (Token: f6ce0ac9e7fb13)
 * Author: M2 - Frontend & SOC Dashboard Lead
 */

const CONFIG = {
  apiBaseUrl: 'http://127.0.0.1:8000',
  pollIntervalMs: 2000,
  ipinfoToken: 'f6ce0ac9e7fb13',
  defaultCoords: [50.1109, 8.6821], // Default: Frankfurt, Germany
};

const state = {
  isBackendConnected: false,
  activeFilter: 'all',
  map: null,
  mapMarker: null,
  events: [],
  stats: { totalEvents: 0, threats: 0, highRisk: 0, activeSessions: 0 },
  risk: { score: 0, label: 'LOW', breakdown: [] },
  journey: [],
  aiAnalysis: { summary: '', evidence: [], recommendations: [] },
  prediction: { stage: 'RECONNAISSANCE', confidence: 0, basis: '' },
  geo: { status: 'unavailable', city: 'Unknown', country: 'Unknown', ip: 'N/A', coords: CONFIG.defaultCoords }
};

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initLeafletMap();
  initEventListeners();
  
  // Initial Geolocation lookup via IPInfo Token
  lookupIpGeo('185.220.101.5');
  
  fetchDashboardData();
  setInterval(fetchDashboardData, CONFIG.pollIntervalMs);
});

function initClock() {
  const clockEl = document.getElementById('clock-display');
  function updateTime() {
    const now = new Date();
    clockEl.innerText = now.toUTCString().split(' ')[4] + ' UTC';
  }
  updateTime();
  setInterval(updateTime, 1000);
}

function initEventListeners() {
  document.getElementById('btn-demo-panel').addEventListener('click', () => {
    const panel = document.getElementById('demo-controller');
    panel.classList.toggle('hidden');
  });

  document.getElementById('btn-reset').addEventListener('click', handleResetDemo);

  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      tabBtns.forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      state.activeFilter = e.target.getAttribute('data-filter');
      renderEventTable();
    });
  });
}

function initLeafletMap() {
  const mapContainer = document.getElementById('leaflet-map');
  if (!mapContainer || typeof L === 'undefined') return;

  state.map = L.map('leaflet-map', {
    center: CONFIG.defaultCoords,
    zoom: 4,
    zoomControl: false,
    attributionControl: false
  });

  // Clean Light CartoDB Tiles
  L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {
    maxZoom: 19
  }).addTo(state.map);

  const customIcon = L.divIcon({
    className: 'custom-map-pin',
    html: `<div style="width:14px;height:14px;background:#ef4444;border-radius:50%;box-shadow:0 0 0 4px rgba(239, 68, 68, 0.2);border:2px solid #ffffff;"></div>`,
    iconSize: [14, 14]
  });

  state.mapMarker = L.marker(CONFIG.defaultCoords, { icon: customIcon }).addTo(state.map);
}

/**
 * IPInfo Geolocation API Lookup
 * Uses Token: f6ce0ac9e7fb13
 */
async function lookupIpGeo(ip) {
  if (!ip || ip === '127.0.0.1' || ip === 'localhost') {
    // If local IP, query client public IP via IPInfo API
    try {
      const res = await fetch(`https://ipinfo.io/json?token=${CONFIG.ipinfoToken}`);
      if (res.ok) {
        const data = await res.json();
        applyGeoData(data);
        return;
      }
    } catch (e) {
      console.warn('IPInfo self-lookup fallback:', e);
    }
  }

  try {
    const res = await fetch(`https://ipinfo.io/${ip}/json?token=${CONFIG.ipinfoToken}`);
    if (res.ok) {
      const data = await res.json();
      applyGeoData(data);
    }
  } catch (err) {
    console.warn('IPInfo lookup error:', err);
    updateMapPosition(CONFIG.defaultCoords[0], CONFIG.defaultCoords[1], 'Frankfurt', 'Germany', ip || '185.220.101.5');
  }
}

function applyGeoData(data) {
  if (data && data.loc) {
    const [lat, lng] = data.loc.split(',').map(Number);
    updateMapPosition(lat, lng, data.city || 'Unknown City', data.country || 'Unknown Country', data.ip || 'N/A');
  }
}

function updateMapPosition(lat, lng, city, country, ip) {
  if (!state.map || !lat || !lng) return;
  state.map.setView([lat, lng], 5);
  if (state.mapMarker) {
    state.mapMarker.setLatLng([lat, lng]);
    state.mapMarker.bindPopup(`<b>Attacker IP:</b> ${ip}<br><b>Location:</b> ${city}, ${country}`).openPopup();
  }

  const infoBox = document.getElementById('map-info-box');
  const titleEl = document.getElementById('map-location-title');
  const coordsEl = document.getElementById('map-location-coords');
  const statusEl = document.getElementById('geo-status-text');

  if (infoBox && titleEl && coordsEl) {
    infoBox.classList.remove('hidden');
    titleEl.innerText = `${city}, ${country}`;
    coordsEl.innerText = `IP: ${ip} (${lat.toFixed(2)}, ${lng.toFixed(2)})`;
  }
  if (statusEl) {
    statusEl.innerText = `${city}, ${country}`;
  }
}

async function fetchDashboardData() {
  try {
    const healthRes = await fetch(`${CONFIG.apiBaseUrl}/health`, { signal: AbortSignal.timeout(1200) });
    if (healthRes.ok) {
      setBackendConnectedStatus(true);
      await fetchFromBackend();
      return;
    }
  } catch (err) {
    setBackendConnectedStatus(false);
    runSimulatedBackendEngine();
  }
}

function setBackendConnectedStatus(isConnected) {
  state.isBackendConnected = isConnected;
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  
  if (isConnected) {
    dot.className = 'status-dot pulse';
    text.innerText = 'API Connected';
  } else {
    dot.className = 'status-dot offline';
    text.innerText = 'Demo Simulation Engine';
  }
}

async function fetchFromBackend() {
  try {
    const [statsRes, eventsRes, riskRes, journeyRes, aiRes, predRes, geoRes] = await Promise.allSettled([
      fetch(`${CONFIG.apiBaseUrl}/api/stats`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/events`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/risk`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/journey`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/analysis`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/prediction`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/geo`).then(r => r.json())
    ]);

    if (statsRes.status === 'fulfilled') {
      state.stats.totalEvents = statsRes.value.total_events || 0;
      state.stats.threats = statsRes.value.threats_detected || 0;
      state.stats.highRisk = statsRes.value.high_risk_sessions || 0;
      state.stats.activeSessions = statsRes.value.active_sessions || 0;
    }

    if (eventsRes.status === 'fulfilled' && Array.isArray(eventsRes.value)) {
      state.events = eventsRes.value;
      if (eventsRes.value.length > 0 && eventsRes.value[0].source_ip) {
        lookupIpGeo(eventsRes.value[0].source_ip);
      }
    }

    if (riskRes.status === 'fulfilled') {
      state.risk.score = riskRes.value.score || 0;
      state.risk.label = riskRes.value.severity_label || 'LOW';
      state.risk.breakdown = riskRes.value.breakdown || [];
    }

    if (journeyRes.status === 'fulfilled') {
      state.journey = journeyRes.value.nodes || [];
    }

    if (aiRes.status === 'fulfilled') {
      state.aiAnalysis.summary = aiRes.value.summary || '';
      state.aiAnalysis.evidence = aiRes.value.evidence || [];
      state.aiAnalysis.recommendations = aiRes.value.recommendations || [];
    }

    if (predRes.status === 'fulfilled') {
      state.prediction.stage = predRes.value.next_stage || 'RECONNAISSANCE';
      state.prediction.confidence = predRes.value.pattern_confidence || 0;
      state.prediction.basis = predRes.value.basis || '';
    }

    if (geoRes.status === 'fulfilled' && geoRes.value.status === 'available') {
      updateMapPosition(
        geoRes.value.latitude,
        geoRes.value.longitude,
        geoRes.value.city,
        geoRes.value.country,
        geoRes.value.ip
      );
    }

    renderAllComponents();

  } catch (e) {
    console.warn('Backend fetch error:', e);
  }
}

let simStepCount = 0;

function runSimulatedBackendEngine() {
  if (state.events.length === 0) {
    seedInitialDemoData();
  }

  simStepCount++;
  if (simStepCount % 4 === 0) {
    simulateIncomingEvent();
  }

  renderAllComponents();
}

function seedInitialDemoData() {
  state.events = [
    { event_id: 'evt_1001', timestamp: '14:31:04', page: 'login', action: 'Failed Authentication Attempt', event_type: 'authentication', severity: 'HIGH', source_ip: '185.220.101.5' },
    { event_id: 'evt_1002', timestamp: '14:31:08', page: 'admin', action: 'Endpoint Enumeration Probed', event_type: 'scanning', severity: 'MEDIUM', source_ip: '185.220.101.5' },
    { event_id: 'evt_1003', timestamp: '14:31:13', page: 'database', action: 'SQL Query Injection Detected', event_type: 'sqli', severity: 'CRITICAL', source_ip: '185.220.101.5' },
    { event_id: 'evt_1004', timestamp: '14:31:18', page: 'backup', action: 'Decoy Backup Resource Accessed', event_type: 'sensitive_access', severity: 'CRITICAL', source_ip: '185.220.101.5' },
    { event_id: 'evt_1005', timestamp: '14:31:25', page: 'api', action: 'Internal API Schema Probed', event_type: 'enumeration', severity: 'HIGH', source_ip: '185.220.101.5' }
  ];

  state.stats = {
    totalEvents: 148,
    threats: 42,
    highRisk: 3,
    activeSessions: 5
  };

  state.risk = {
    score: 87,
    label: 'CRITICAL',
    breakdown: [
      { signal: 'Brute-Force Login Pattern', points: 20 },
      { signal: 'Endpoint Scanning & Discovery', points: 20 },
      { signal: 'SQL Injection Syntax Match', points: 30 },
      { signal: 'Decoy Backup Resource Access', points: 17 }
    ]
  };

  state.journey = [
    { step: 1, page: 'LOGIN', action: 'Failed Auth Attempt', timestamp: '14:31:04', status: 'warning' },
    { step: 2, page: 'ADMIN', action: 'Resource Enumeration', timestamp: '14:31:08', status: 'warning' },
    { step: 3, page: 'DATABASE', action: 'SQL Injection Pattern', timestamp: '14:31:13', status: 'critical' },
    { step: 4, page: 'BACKUP', action: 'Sensitive File Access', timestamp: '14:31:18', status: 'critical' },
    { step: 5, page: 'API', action: 'API Endpoint Probing', timestamp: '14:31:25', status: 'critical' }
  ];

  state.aiAnalysis = {
    summary: 'Session sess_8832 initiated credential brute-forcing against the corporate login trap before escalating to administrative discovery and submitting malicious SQL payloads.',
    evidence: [
      'Multiple failed authentication attempts logged within 5 seconds on login trap',
      'Administrative directory scanning detected across /admin endpoints',
      'SQL injection query pattern matched in synthetic database console',
      'Decoy backup archive accessed without valid authorization'
    ],
    recommendations: [
      'Apply immediate firewall drop rule for IP 185.220.101.5',
      'Revoke active session token sess_8832',
      'Inspect corporate edge logs for correlated IP activity'
    ]
  };

  state.prediction = {
    stage: 'PRIVILEGE ESCALATION',
    confidence: 78,
    basis: 'Pattern match: Credential Access -> Data Probing -> Estimated Next Stage'
  };

  lookupIpGeo('185.220.101.5');
}

function simulateIncomingEvent() {
  const actions = [
    { page: 'search', action: 'Path Traversal Syntax Probed', type: 'traversal', sev: 'HIGH' },
    { page: 'api', action: 'JWT Secret Probing Attempt', type: 'authentication', sev: 'CRITICAL' },
    { page: 'login', action: 'Brute force credential attempt', type: 'authentication', sev: 'MEDIUM' }
  ];
  const choice = actions[Math.floor(Math.random() * actions.length)];
  const timeStr = new Date().toTimeString().split(' ')[0];

  state.events.unshift({
    event_id: 'evt_' + Math.floor(1000 + Math.random() * 9000),
    timestamp: timeStr,
    page: choice.page,
    action: choice.action,
    event_type: choice.type,
    severity: choice.sev,
    source_ip: '185.220.101.5'
  });

  state.stats.totalEvents++;
  if (choice.sev === 'CRITICAL' || choice.sev === 'HIGH') {
    state.stats.threats++;
  }
}

function renderAllComponents() {
  renderStatsCards();
  renderEventTable();
  renderRiskPanel();
  renderJourney();
  renderAiAnalysis();
  renderPrediction();
}

function renderStatsCards() {
  document.getElementById('stat-total-events').innerText = state.stats.totalEvents;
  document.getElementById('stat-threats').innerText = state.stats.threats;
  document.getElementById('stat-high-risk').innerText = state.stats.highRisk;
  document.getElementById('stat-active-sessions').innerText = state.stats.activeSessions;
}

function renderEventTable() {
  const tbody = document.getElementById('event-table-body');
  if (!tbody) return;

  const filtered = state.events.filter(e => {
    if (state.activeFilter === 'all') return true;
    return e.severity === state.activeFilter;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#64748b;padding:20px;">No matching events logged for severity '${state.activeFilter}'</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.slice(0, 30).map(e => `
    <tr>
      <td>${e.timestamp}</td>
      <td><span class="endpoint-chip">/${e.page}</span></td>
      <td style="color:#0f172a;font-weight:500;">${e.action}</td>
      <td>${e.event_type}</td>
      <td><span class="chip-sev chip-${(e.severity || 'low').toLowerCase()}">${e.severity || 'LOW'}</span></td>
      <td style="font-family:var(--font-mono);">${e.source_ip || '127.0.0.1'}</td>
    </tr>
  `).join('');
}

function renderRiskPanel() {
  const scoreValEl = document.getElementById('risk-score-val');
  const circleEl = document.getElementById('risk-circle');
  const tagEl = document.getElementById('risk-severity-tag');
  const listEl = document.getElementById('risk-breakdown-list');

  const score = Math.min(100, Math.max(0, state.risk.score));
  scoreValEl.innerText = score;

  const angle = (score / 100) * 360;
  circleEl.style.setProperty('--risk-angle', `${angle}`);

  let chipClass = 'chip-low';
  let labelText = 'LOW';
  if (score >= 80) { chipClass = 'chip-critical'; labelText = 'CRITICAL'; }
  else if (score >= 60) { chipClass = 'chip-high'; labelText = 'HIGH'; }
  else if (score >= 30) { chipClass = 'chip-medium'; labelText = 'MEDIUM'; }

  tagEl.className = `badge-chip ${chipClass}`;
  tagEl.innerText = state.risk.label || labelText;

  if (!state.risk.breakdown || state.risk.breakdown.length === 0) {
    listEl.innerHTML = `<li class="signal-empty">No active risk signals.</li>`;
  } else {
    listEl.innerHTML = state.risk.breakdown.map(item => `
      <li class="signal-item">
        <span>• ${item.signal}</span>
        <span class="signal-points">+${item.points}</span>
      </li>
    `).join('');
  }
}

function renderJourney() {
  const container = document.getElementById('journey-container');
  if (!container) return;

  if (!state.journey || state.journey.length === 0) {
    container.innerHTML = `<div class="journey-empty">Awaiting attacker session movement...</div>`;
    return;
  }

  container.innerHTML = state.journey.map((node, index) => {
    const isLast = index === state.journey.length - 1;
    const boxClass = node.status === 'critical' ? 'step-card critical' : 'step-card active';
    return `
      <div class="journey-step">
        <div class="${boxClass}">
          <span class="step-num">Step 0${node.step || (index + 1)}</span>
          <h4 class="step-endpoint">/${node.page}</h4>
          <span class="step-desc">${node.action}</span>
          <div class="step-time">${node.timestamp}</div>
        </div>
        ${!isLast ? `<i class="fa-solid fa-chevron-right step-arrow"></i>` : ''}
      </div>
    `;
  }).join('');
}

function renderAiAnalysis() {
  const summaryEl = document.getElementById('ai-summary-text');
  const evidenceEl = document.getElementById('ai-evidence-list');
  const recommendEl = document.getElementById('ai-recommend-list');

  if (summaryEl) summaryEl.innerText = state.aiAnalysis.summary || 'Awaiting telemetry evidence for synthesis...';

  if (evidenceEl) {
    if (!state.aiAnalysis.evidence || state.aiAnalysis.evidence.length === 0) {
      evidenceEl.innerHTML = `<li>No evidence compiled yet.</li>`;
    } else {
      evidenceEl.innerHTML = state.aiAnalysis.evidence.map(item => `<li>${item}</li>`).join('');
    }
  }

  if (recommendEl) {
    if (!state.aiAnalysis.recommendations || state.aiAnalysis.recommendations.length === 0) {
      recommendEl.innerHTML = `<li>Monitoring active session...</li>`;
    } else {
      recommendEl.innerHTML = state.aiAnalysis.recommendations.map(item => `<li>${item}</li>`).join('');
    }
  }
}

function renderPrediction() {
  const stageEl = document.getElementById('predict-stage-name');
  const confValEl = document.getElementById('predict-confidence-val');
  const confBarEl = document.getElementById('predict-confidence-bar');
  const basisEl = document.getElementById('predict-basis-text');

  if (stageEl) stageEl.innerText = (state.prediction.stage || 'RECONNAISSANCE').toUpperCase();
  if (confValEl) confValEl.innerText = `${state.prediction.confidence || 0}%`;
  if (confBarEl) confBarEl.style.width = `${state.prediction.confidence || 0}%`;
  if (basisEl) basisEl.innerText = state.prediction.basis || 'Pattern-based estimation active...';
}

function triggerSimulatedAttack(type) {
  const timeStr = new Date().toTimeString().split(' ')[0];

  if (type === 'brute_force') {
    state.events.unshift({
      event_id: 'evt_sim_' + Math.floor(Math.random() * 1000),
      timestamp: timeStr,
      page: 'login',
      action: 'Rapid Failed Login Attempt (Brute-Force)',
      event_type: 'authentication',
      severity: 'HIGH',
      source_ip: '185.220.101.5'
    });
    state.risk.score = Math.min(100, state.risk.score + 20);
    state.risk.breakdown.push({ signal: 'Brute-Force Login Pattern', points: 20 });
    state.stats.threats++;
  } else if (type === 'scanning') {
    state.events.unshift({
      event_id: 'evt_sim_' + Math.floor(Math.random() * 1000),
      timestamp: timeStr,
      page: 'admin',
      action: 'Automated Port & Resource Scan',
      event_type: 'scanning',
      severity: 'MEDIUM',
      source_ip: '185.220.101.5'
    });
    state.risk.score = Math.min(100, state.risk.score + 15);
    state.risk.breakdown.push({ signal: 'Endpoint Scanning Activity', points: 15 });
  } else if (type === 'sqli') {
    state.events.unshift({
      event_id: 'evt_sim_' + Math.floor(Math.random() * 1000),
      timestamp: timeStr,
      page: 'database',
      action: 'Malicious SQL Payload Injection Detected',
      event_type: 'sqli',
      severity: 'CRITICAL',
      source_ip: '185.220.101.5'
    });
    state.risk.score = Math.min(100, state.risk.score + 30);
    state.risk.breakdown.push({ signal: 'SQL Injection Pattern', points: 30 });
    state.stats.highRisk++;
    state.stats.threats++;
  } else if (type === 'full_chain') {
    seedInitialDemoData();
  }

  renderAllComponents();
}

async function handleResetDemo() {
  if (state.isBackendConnected) {
    try {
      await fetch(`${CONFIG.apiBaseUrl}/api/reset`, { method: 'POST' });
    } catch (e) {
      console.warn('Reset API failed', e);
    }
  }

  state.events = [];
  state.stats = { totalEvents: 0, threats: 0, highRisk: 0, activeSessions: 1 };
  state.risk = { score: 0, label: 'LOW', breakdown: [] };
  state.journey = [];
  state.aiAnalysis = { summary: 'System reset. Awaiting telemetry...', evidence: [], recommendations: [] };
  state.prediction = { stage: 'RECONNAISSANCE', confidence: 0, basis: 'System baseline reset' };

  renderAllComponents();
}
