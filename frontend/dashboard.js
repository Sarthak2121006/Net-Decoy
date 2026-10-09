/**
 * NetDecoy — SOC Dashboard JavaScript Engine (Modern Enterprise Light Theme)
 * Integrated with IPInfo Geolocation API (Token: f6ce0ac9e7fb13)
 * Author: M2 - Frontend & SOC Dashboard Lead
 */

const CONFIG = {
  apiBaseUrl: (typeof window !== 'undefined' && window.location.origin && window.location.origin.startsWith('http') && !window.location.origin.includes('5500')) 
    ? window.location.origin 
    : 'http://localhost:5000',
  pollIntervalMs: 2000,
  ipinfoToken: 'f6ce0ac9e7fb13',
  defaultCoords: [50.1109, 8.6821], // Frankfurt, Germany
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
  const demoBtn = document.getElementById('btn-demo-panel');
  if (demoBtn) {
    demoBtn.addEventListener('click', () => {
      const panel = document.getElementById('demo-controller');
      if (panel) panel.classList.toggle('hidden');
    });
  }

  const resetBtn = document.getElementById('btn-reset');
  if (resetBtn) {
    resetBtn.addEventListener('click', handleResetSession);
  }

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

  // OpenStreetMap Tiles
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19,
    subdomains: ['a', 'b', 'c']
  }).addTo(state.map);

  const customIcon = L.divIcon({
    className: 'custom-map-pin',
    html: `<div style="width:16px;height:16px;background:#ef4444;border-radius:50%;box-shadow:0 0 0 4px rgba(239, 68, 68, 0.25);border:2px solid #ffffff;"></div>`,
    iconSize: [16, 16],
    iconAnchor: [8, 8]
  });

  state.mapMarker = L.marker(CONFIG.defaultCoords, { icon: customIcon }).addTo(state.map);

  setTimeout(() => {
    if (state.map) {
      state.map.invalidateSize();
    }
  }, 250);
}

async function lookupIpGeo(ip) {
  if (!ip || ip === '127.0.0.1' || ip === 'localhost') {
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
    const healthRes = await fetch(`${CONFIG.apiBaseUrl}/api/health`, { signal: AbortSignal.timeout(1500) });
    if (healthRes.ok) {
      setBackendConnectedStatus(true);
      await fetchFromBackend();
      return;
    }
  } catch (err) {
    try {
      const healthResFallback = await fetch(`${CONFIG.apiBaseUrl}/health`, { signal: AbortSignal.timeout(1500) });
      if (healthResFallback.ok) {
        setBackendConnectedStatus(true);
        await fetchFromBackend();
        return;
      }
    } catch (err2) {
      setBackendConnectedStatus(false);
      runSimulatedBackendEngine();
    }
  }
}

function setBackendConnectedStatus(isConnected) {
  state.isBackendConnected = isConnected;
  const dot = document.getElementById('status-dot');
  if (dot) {
    dot.className = isConnected ? 'status-dot-active' : 'status-dot-simulated';
  }
  const badge = document.getElementById('system-status-badge');
  if (badge) {
    badge.innerText = isConnected ? 'Backend: Live' : 'Backend: Simulation Mode';
    badge.className = isConnected ? 'badge badge-success' : 'badge badge-warning';
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

    if (statsRes.status === 'fulfilled' && statsRes.value) {
      state.stats.totalEvents = statsRes.value.total_events || 0;
      state.stats.threats = statsRes.value.threats_detected || 0;
      state.stats.highRisk = statsRes.value.high_risk || statsRes.value.high_risk_sessions || 0;
      state.stats.activeSessions = statsRes.value.total_sessions || statsRes.value.active_sessions || 0;
    }

    if (eventsRes.status === 'fulfilled' && eventsRes.value) {
      const evList = Array.isArray(eventsRes.value) ? eventsRes.value : (eventsRes.value.events || []);
      state.events = evList;
      if (evList.length > 0 && evList[0].source_ip) {
        lookupIpGeo(evList[0].source_ip);
      }
    }

    if (riskRes.status === 'fulfilled' && riskRes.value) {
      state.risk.score = riskRes.value.score || 0;
      state.risk.label = riskRes.value.level || riskRes.value.severity_label || 'LOW';
      const rawBreakdown = riskRes.value.breakdown;
      if (Array.isArray(rawBreakdown)) {
        state.risk.breakdown = rawBreakdown;
      } else if (rawBreakdown && typeof rawBreakdown === 'object') {
        state.risk.breakdown = Object.entries(rawBreakdown).map(([k, v]) => ({
          signal: k.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
          points: v
        }));
      }
    }

    if (journeyRes.status === 'fulfilled' && journeyRes.value) {
      const journeyData = journeyRes.value;
      if (Array.isArray(journeyData.nodes)) {
        state.journey = journeyData.nodes;
      } else if (Array.isArray(journeyData.stages)) {
        state.journey = journeyData.stages.map((s, idx) => ({
          step: idx + 1,
          page: s.page || s.stage || 'trap',
          action: s.action || s.description || s.stage || 'interaction',
          timestamp: s.timestamp ? s.timestamp.substring(11, 19) : '00:00:00',
          status: (s.severity === 'CRITICAL' || s.severity === 'HIGH') ? 'critical' : 'warning'
        }));
      } else if (Array.isArray(journeyData.timeline)) {
        state.journey = journeyData.timeline.map(t => ({
          step: t.step || 1,
          page: t.page || 'trap',
          action: t.detail || t.action || 'interaction',
          timestamp: t.timestamp ? t.timestamp.substring(11, 19) : '00:00:00',
          status: t.detection ? 'critical' : 'warning'
        }));
      }
    }

    if (aiRes.status === 'fulfilled' && aiRes.value) {
      state.aiAnalysis.summary = aiRes.value.summary || aiRes.value.analysis || '';
      state.aiAnalysis.evidence = aiRes.value.evidence || [];
      state.aiAnalysis.recommendations = aiRes.value.recommendations || aiRes.value.recommended_actions || [];
    }

    if (predRes.status === 'fulfilled' && predRes.value) {
      state.prediction.stage = predRes.value.next_stage || 'RECONNAISSANCE';
      state.prediction.confidence = predRes.value.confidence || predRes.value.pattern_confidence || 0;
      state.prediction.basis = predRes.value.basis || '';
    }

    if (geoRes.status === 'fulfilled' && (geoRes.value.status === 'available' || geoRes.value.available === true)) {
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
    event_id: 'evt_sim_' + Math.floor(1000 + Math.random() * 9000),
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
  renderDetectedAttacks();
  renderEventTable();
  renderRiskPanel();
  renderJourney();
  renderAiAnalysis();
  renderPrediction();
}

function renderDetectedAttacks() {
  const container = document.getElementById('detected-attacks-list');
  const countBadge = document.getElementById('attacks-count-badge');
  if (!container) return;

  const detectedMap = new Map();

  state.events.forEach(e => {
    const act = (e.action || '').toLowerCase();
    const type = (e.event_type || '').toLowerCase();
    const page = e.page || 'trap';

    if (type === 'sqli' || act.includes('sql') || act.includes('injection')) {
      detectedMap.set('sqli', {
        name: 'SQL Injection Payload Attack',
        icon: 'fa-code',
        severity: 'critical',
        page: `/${page}`,
        detail: 'Harmful SQL syntax pattern identified in database trap'
      });
    } else if (type === 'authentication' || act.includes('failed_login') || act.includes('brute_force')) {
      detectedMap.set('brute_force', {
        name: 'Credential Brute-Force Spray',
        icon: 'fa-key',
        severity: 'high',
        page: `/${page}`,
        detail: 'Repeated authentication failures detected within short window'
      });
    } else if (type === 'traversal' || act.includes('traversal') || act.includes('directory')) {
      detectedMap.set('traversal', {
        name: 'Directory / Path Traversal Attack',
        icon: 'fa-folder-tree',
        severity: 'high',
        page: `/${page}`,
        detail: 'Dot-dot-slash sequence probed against backup portal'
      });
    } else if (type === 'scanning' || act.includes('scan') || act.includes('probe') || act.includes('swagger')) {
      detectedMap.set('scanning', {
        name: 'Automated Port & Route Discovery Scan',
        icon: 'fa-radar',
        severity: 'medium',
        page: `/${page}`,
        detail: 'Enumeration of administrative endpoints and hidden paths'
      });
    } else if (type === 'sensitive_access' || act.includes('backup') || act.includes('exfiltration')) {
      detectedMap.set('exfiltration', {
        name: 'Confidential Backup & Data Exfiltration',
        icon: 'fa-database',
        severity: 'critical',
        page: `/${page}`,
        detail: 'Unauthorized download attempt on enterprise database archive'
      });
    } else if (type === 'privilege_escalation' || act.includes('privilege')) {
      detectedMap.set('privilege_escalation', {
        name: 'Privilege Escalation Probing',
        icon: 'fa-user-shield',
        severity: 'critical',
        page: `/${page}`,
        detail: 'Role assignment token override attempt detected'
      });
    }
  });

  const attackList = Array.from(detectedMap.values());

  if (countBadge) {
    countBadge.textContent = `${attackList.length} Active Threat Pattern${attackList.length === 1 ? '' : 's'}`;
    countBadge.style.background = attackList.length > 0 ? '#fef2f2' : '#f0fdf4';
    countBadge.style.color = attackList.length > 0 ? '#991b1b' : '#166534';
    countBadge.style.borderColor = attackList.length > 0 ? '#fecaca' : '#bbf7d0';
  }

  if (attackList.length === 0) {
    container.innerHTML = `
      <div class="no-attacks-msg">
        <i class="fa-solid fa-circle-check" style="color:#10b981;"></i> System Baseline Normal — Monitoring honeypot traps for active intrusion attempts.
      </div>
    `;
    return;
  }

  container.innerHTML = attackList.map(atk => `
    <div class="attack-pill pill-${atk.severity}" title="${atk.detail}">
      <i class="fa-solid ${atk.icon}"></i>
      <span>${atk.name}</span>
      <span class="attack-pill-page">${atk.page}</span>
    </div>
  `).join('');
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
    container.innerHTML = `<div class="journey-empty">Awaiting session activity...</div>`;
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

  if (summaryEl) summaryEl.innerText = state.aiAnalysis.summary || 'Awaiting telemetry evidence...';

  if (evidenceEl) {
    if (!state.aiAnalysis.evidence || state.aiAnalysis.evidence.length === 0) {
      evidenceEl.innerHTML = `<li>No evidence compiled yet.</li>`;
    } else {
      evidenceEl.innerHTML = state.aiAnalysis.evidence.map(item => `<li>${item}</li>`).join('');
    }
  }

  if (recommendEl) {
    if (!state.aiAnalysis.recommendations || state.aiAnalysis.recommendations.length === 0) {
      recommendEl.innerHTML = `<li>No action required.</li>`;
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
  if (basisEl) basisEl.innerText = state.prediction.basis || 'Pattern trajectory matching active.';
}

function triggerSimulatedAttack(type) {
  const timeStr = new Date().toTimeString().split(' ')[0];
  let simEvent = null;

  if (type === 'brute_force') {
    simEvent = {
      session_id: 'sess_live_demo',
      source_ip: '185.220.101.5',
      page: 'login',
      action: 'failed_login',
      event_type: 'authentication',
      severity: 'HIGH',
      payload: { username: 'admin', attempt: 'brute_force' }
    };
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
    simEvent = {
      session_id: 'sess_live_demo',
      source_ip: '185.220.101.5',
      page: 'admin',
      action: 'unauthorized_admin_access',
      event_type: 'scanning',
      severity: 'MEDIUM',
      payload: { scan_target: '/admin/users' }
    };
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
    simEvent = {
      session_id: 'sess_live_demo',
      source_ip: '185.220.101.5',
      page: 'database',
      action: 'sql_injection_attempt',
      event_type: 'sqli',
      severity: 'CRITICAL',
      payload: { query: "SELECT * FROM users WHERE user='admin' OR 1=1--" }
    };
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

  if (simEvent && state.isBackendConnected) {
    fetch(`${CONFIG.apiBaseUrl}/api/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(simEvent)
    }).then(() => fetchDashboardData()).catch(e => console.debug(e));
  }

  renderAllComponents();
}

async function handleResetSession() {
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

// ==========================================
// EXECUTIVE FORENSIC SOC REPORT CONTROLLER
// ==========================================
let activeReportDossier = null;

async function openForensicReportModal() {
  const modal = document.getElementById('reportModalOverlay');
  if (!modal) return;

  try {
    const res = await fetch(`${CONFIG.apiBaseUrl}/api/report`);
    if (res.ok) {
      activeReportDossier = await res.json();
    }
  } catch (err) {
    console.debug('Failed fetching /api/report, compiling from state:', err);
  }

  // If backend was offline or empty, build fallback dossier from current state
  if (!activeReportDossier || !activeReportDossier.incident_reference_id) {
    const sessId = (state.events[0] && state.events[0].session_id) || 'sess_demo_alpha';
    activeReportDossier = {
      incident_reference_id: 'INC-2026-' + Math.floor(1000 + Math.random() * 9000),
      report_timestamp: new Date().toUTCString(),
      session_id: sessId,
      primary_attacker_ip: (state.events[0] && state.events[0].source_ip) || '185.220.101.5',
      threat_actor_classification: state.risk.score > 60 ? 'Advanced Exploitation Script' : 'Reconnaissance Bot',
      risk_assessment: {
        score: state.risk.score,
        severity_level: state.risk.label || 'HIGH',
        signal_breakdown: state.risk.breakdown
      },
      mitre_attack_framework: [
        { id: 'T1190', name: 'Exploit Public-Facing Application (SQLi)', tactic: 'Initial Access', description: 'SQL injection payload evaluated against database console.' },
        { id: 'T1110.003', name: 'Password Spraying / Brute Force', tactic: 'Credential Access', description: 'Rapid failed authentications observed on SSO login gateway.' },
        { id: 'T1083', name: 'File & Directory Discovery (Traversal)', tactic: 'Discovery', description: 'Directory traversal sequence tested on backup archive portal.' }
      ],
      forensic_timeline: state.events.map((e, idx) => ({
        step: idx + 1,
        timestamp: e.timestamp,
        endpoint: `/${e.page}`,
        action: e.action,
        severity: e.severity,
        source_ip: e.source_ip || '185.220.101.5'
      })),
      raw_payload_evidence: state.events.filter(e => e.severity === 'CRITICAL' || e.severity === 'HIGH').map(e => ({
        timestamp: e.timestamp,
        target_route: `/${e.page}`,
        attack_type: e.event_type || 'Exploit Payload',
        payload_snippet: typeof e.payload === 'object' ? JSON.stringify(e.payload) : (e.action || 'Payload match'),
        severity: e.severity
      })),
      ai_threat_synthesis: {
        summary: state.aiAnalysis.summary || 'Adversary activity detected across multiple deception honeypots.',
        evidence_bullets: state.aiAnalysis.evidence || [],
        containment_directives: state.aiAnalysis.recommendations || [
          'Apply perimeter firewall block rule for attacking IP',
          'Invalidate and cycle active session authentication tokens',
          'Deploy honeypot SQL tarpit to exhaust automated scanner'
        ]
      },
      predictive_forecasting: {
        estimated_next_stage: state.prediction.stage || 'PRIVILEGE ESCALATION',
        pattern_confidence: state.prediction.confidence || 86,
        basis: state.prediction.basis || 'Kill-chain trajectory matches credential probing followed by administrative escalation.'
      }
    };
  }

  // Populate Document Fields
  document.getElementById('rep-incident-id').textContent = activeReportDossier.incident_reference_id;
  document.getElementById('rep-timestamp').textContent = activeReportDossier.report_timestamp;
  document.getElementById('rep-session-id').textContent = activeReportDossier.session_id;
  document.getElementById('rep-threat-profile').textContent = activeReportDossier.threat_actor_classification;
  document.getElementById('rep-summary-text').textContent = activeReportDossier.ai_threat_synthesis.summary;
  document.getElementById('rep-risk-score').textContent = `${activeReportDossier.risk_assessment.score}/100`;
  
  const riskLvlEl = document.getElementById('rep-risk-level');
  riskLvlEl.textContent = activeReportDossier.risk_assessment.severity_level;
  riskLvlEl.className = `badge-chip chip-${(activeReportDossier.risk_assessment.severity_level || 'low').toLowerCase()}`;
  document.getElementById('rep-attacker-ip').textContent = activeReportDossier.primary_attacker_ip;

  // Populate MITRE Table
  const mitreBody = document.getElementById('rep-mitre-body');
  if (mitreBody) {
    const mitreList = activeReportDossier.mitre_attack_framework || [];
    mitreBody.innerHTML = mitreList.map(m => `
      <tr>
        <td><code style="color:var(--accent-primary); font-weight:700;">${m.id}</code></td>
        <td><strong>${m.name}</strong></td>
        <td><span class="badge-chip chip-medium">${m.tactic}</span></td>
        <td style="color:#475569;">${m.description}</td>
      </tr>
    `).join('') || `<tr><td colspan="4" style="text-align:center; color:#94a3b8;">No specific MITRE techniques matched.</td></tr>`;
  }

  // Populate Forensic Timeline Table
  const timeBody = document.getElementById('rep-timeline-body');
  if (timeBody) {
    const timeline = activeReportDossier.forensic_timeline || [];
    timeBody.innerHTML = timeline.slice(0, 15).map(t => `
      <tr>
        <td style="font-family:var(--font-mono); font-weight:700;">#0${t.step}</td>
        <td>${t.timestamp}</td>
        <td><span class="endpoint-chip">${t.endpoint}</span></td>
        <td style="font-weight:600; color:#0f172a;">${t.action}</td>
        <td><span class="chip-sev chip-${(t.severity || 'low').toLowerCase()}">${t.severity || 'LOW'}</span></td>
        <td style="font-family:var(--font-mono);">${t.source_ip}</td>
      </tr>
    `).join('') || `<tr><td colspan="6" style="text-align:center; color:#94a3b8;">Awaiting session interactions.</td></tr>`;
  }

  // Populate Raw Payload Evidence Box
  const evBox = document.getElementById('rep-evidence-container');
  if (evBox) {
    const evList = activeReportDossier.raw_payload_evidence || [];
    if (evList.length === 0) {
      evBox.innerHTML = `<div style="color:#64748b; font-size:12px; font-style:italic;">No critical/high severity payload signatures flagged in this session.</div>`;
    } else {
      evBox.innerHTML = evList.map(e => `
        <div class="evidence-item">
          <div class="ev-header">
            <span class="ev-ts">[${e.timestamp}]</span>
            <span class="ev-target">${e.target_route}</span>
            <span class="chip-sev chip-${(e.severity || 'low').toLowerCase()}">${e.severity || 'HIGH'}</span>
            <span style="color:#f59e0b; font-weight:600;">[${e.attack_type}]</span>
          </div>
          <code class="ev-code">${e.payload_snippet}</code>
        </div>
      `).join('');
    }
  }

  // Populate Containment Directives List
  const dirList = document.getElementById('rep-directives-list');
  if (dirList) {
    const directives = activeReportDossier.ai_threat_synthesis.containment_directives || [];
    dirList.innerHTML = directives.map(d => `
      <li><i class="fa-solid fa-square-check" style="color:#10b981; margin-right:6px;"></i> ${d}</li>
    `).join('') || `<li><i class="fa-solid fa-circle-check" style="color:#10b981;"></i> System operational. No emergency containment required.</li>`;
  }

  // Populate Prediction Section
  document.getElementById('rep-predict-stage').textContent = (activeReportDossier.predictive_forecasting.estimated_next_stage || 'RECONNAISSANCE').toUpperCase();
  document.getElementById('rep-predict-conf').textContent = `${activeReportDossier.predictive_forecasting.pattern_confidence || 75}% Pattern Confidence`;
  document.getElementById('rep-predict-basis').textContent = activeReportDossier.predictive_forecasting.basis;

  // Show modal
  modal.classList.remove('hidden');
}

function closeForensicReportModal() {
  const modal = document.getElementById('reportModalOverlay');
  if (modal) modal.classList.add('hidden');
}

function printReportDocument() {
  window.print();
}

function downloadReportJson() {
  if (!activeReportDossier) return;
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(activeReportDossier, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `${activeReportDossier.incident_reference_id}_SOC_Forensic_Dossier.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}
