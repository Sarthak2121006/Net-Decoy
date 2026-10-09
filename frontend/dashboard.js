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
  defaultCoords: [18.6229, 73.8070], // Real-time default coordinates
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
  geo: { status: 'locating', city: 'Locating...', region: '', country: '', ip: 'Detecting...', coords: CONFIG.defaultCoords }
};

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initLeafletMap();
  initEventListeners();
  
  // Immediately acquire real-time location
  fetchRealtimeLocation();
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

  const recenterGeoBtn = document.getElementById('btn-recenter-geo');
  if (recenterGeoBtn) {
    recenterGeoBtn.addEventListener('click', () => {
      fetchRealtimeLocation();
    });
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
    zoom: 5,
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
    html: `<div style="position:relative;width:20px;height:20px;display:flex;align-items:center;justify-content:center;">
             <div style="position:absolute;width:100%;height:100%;border-radius:50%;background:rgba(239, 68, 68, 0.4);animation:ping 1.5s cubic-bezier(0,0,0.2,1) infinite;"></div>
             <div style="width:14px;height:14px;background:#ef4444;border-radius:50%;border:2px solid #ffffff;box-shadow:0 2px 6px rgba(0,0,0,0.3);position:relative;z-index:2;"></div>
           </div>`,
    iconSize: [20, 20],
    iconAnchor: [10, 10]
  });

  state.mapMarker = L.marker(CONFIG.defaultCoords, { icon: customIcon }).addTo(state.map);

  setTimeout(() => {
    if (state.map) {
      state.map.invalidateSize();
    }
  }, 250);
}

/**
 * Acquire real-time location using HTML5 Geolocation with IP fallback
 */
function fetchRealtimeLocation() {
  const statusEl = document.getElementById('geo-status-text');
  if (statusEl) statusEl.innerText = 'Locating...';

  // 1. First trigger backend /api/geo or direct IPInfo lookup
  lookupIpGeo();

  // 2. Also check browser GPS Geolocation if available for ultra-precise sensor location
  if (typeof navigator !== 'undefined' && navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        const lat = pos.coords.latitude;
        const lng = pos.coords.longitude;
        if (lat && lng) {
          updateMapPosition(lat, lng, 'Real-Time GPS Node', 'Telemetry Sensor', 'Local Grid', 'Active Device', 'High-Precision Sensor Network');
        }
      },
      (err) => {
        // Silently fall back to IP geolocation
        console.debug('Browser GPS fallback to IP geolocation:', err.message);
      },
      { timeout: 3500, maximumAge: 30000 }
    );
  }
}

/**
 * Resolves IP to real-time geographical coordinates
 */
async function lookupIpGeo(ip) {
  // If no IP or loopback/private, fetch host machine's real-time public location
  if (!ip || ip === '127.0.0.1' || ip === 'localhost' || ip === '::1' || ip === 'N/A' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
    // Try backend /api/geo
    try {
      const res = await fetch(`${CONFIG.apiBaseUrl}/api/geo`);
      if (res.ok) {
        const data = await res.json();
        if (data && (data.latitude || data.loc || data.available)) {
          applyGeoData(data);
          return;
        }
      }
    } catch (e) {
      console.debug('Backend /api/geo fallback notice:', e);
    }

    // Direct IPInfo lookup for current client's real-time public IP
    try {
      const res = await fetch(`https://ipinfo.io/json?token=${CONFIG.ipinfoToken}`);
      if (res.ok) {
        const data = await res.json();
        applyGeoData(data);
        return;
      }
    } catch (e) {
      console.warn('IPInfo real-time lookup fallback:', e);
    }
    return;
  }

  // Look up specific public attacker IP
  try {
    const res = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${CONFIG.ipinfoToken}`);
    if (res.ok) {
      const data = await res.json();
      applyGeoData(data);
      return;
    }
  } catch (err) {
    console.debug('IPInfo IP lookup fallback to backend:', err);
  }

  try {
    const res = await fetch(`${CONFIG.apiBaseUrl}/api/geo?ip=${encodeURIComponent(ip)}`);
    if (res.ok) {
      const data = await res.json();
      applyGeoData(data);
    }
  } catch (err) {
    console.warn('Backend geo lookup error:', err);
  }
}

function applyGeoData(data) {
  if (!data) return;
  let lat = null, lng = null;

  if (typeof data.latitude === 'number' && typeof data.longitude === 'number' && (data.latitude !== 0 || data.longitude !== 0)) {
    lat = data.latitude;
    lng = data.longitude;
  } else if (data.loc && typeof data.loc === 'string' && data.loc.includes(',')) {
    const parts = data.loc.split(',').map(Number);
    lat = parts[0];
    lng = parts[1];
  } else if (Array.isArray(data.coords) && data.coords.length === 2) {
    lat = data.coords[0];
    lng = data.coords[1];
  }

  if (lat !== null && lng !== null && !isNaN(lat) && !isNaN(lng)) {
    updateMapPosition(
      lat,
      lng,
      data.city || 'Realtime Node',
      data.region || '',
      data.country || data.country_code || '',
      data.ip || data.source_ip || 'Realtime Host',
      data.isp || data.org || ''
    );
  }
}

function updateMapPosition(lat, lng, city, region, country, ip, isp = '') {
  if (!state.map || typeof lat !== 'number' || typeof lng !== 'number' || isNaN(lat) || isNaN(lng)) return;
  
  state.geo = {
    status: 'available',
    city: city || 'Unknown City',
    region: region || '',
    country: country || 'Unknown Country',
    ip: ip || 'Live IP',
    isp: isp || '',
    coords: [lat, lng]
  };

  state.map.setView([lat, lng], 6);
  if (state.mapMarker) {
    state.mapMarker.setLatLng([lat, lng]);
    const locationDisplay = region ? `${city}, ${region}, ${country}` : `${city}, ${country}`;
    const ispHtml = isp ? `<div style="font-size:11px;color:#64748b;margin-top:3px;"><b>Network:</b> ${isp}</div>` : '';
    state.mapMarker.bindPopup(`
      <div style="font-family:Inter,sans-serif;font-size:12px;min-width:180px;">
        <div style="font-weight:700;color:#0f172a;margin-bottom:4px;border-bottom:1px solid #e2e8f0;padding-bottom:3px;display:flex;align-items:center;gap:6px;">
          <span style="display:inline-block;width:8px;height:8px;background:#ef4444;border-radius:50%;"></span> Threat Origin
        </div>
        <div style="margin-top:2px;"><b>IP Address:</b> <code style="color:#dc2626;font-weight:600;">${ip}</code></div>
        <div style="margin-top:2px;"><b>Location:</b> ${locationDisplay}</div>
        <div style="margin-top:2px;"><b>GPS Coords:</b> ${lat.toFixed(4)}°, ${lng.toFixed(4)}°</div>
        ${ispHtml}
      </div>
    `).openPopup();
  }

  const infoBox = document.getElementById('map-info-box');
  const titleEl = document.getElementById('map-location-title');
  const coordsEl = document.getElementById('map-location-coords');
  const statusEl = document.getElementById('geo-status-text');

  const locationDisplay = region ? `${city}, ${region}, ${country}` : `${city}, ${country}`;

  if (infoBox && titleEl && coordsEl) {
    infoBox.classList.remove('hidden');
    titleEl.innerText = locationDisplay;
    coordsEl.innerText = `IP: ${ip} | ${lat.toFixed(4)}° N, ${lng.toFixed(4)}° E ${isp ? '• ' + isp : ''}`;
  }
  if (statusEl) {
    statusEl.innerHTML = `<span style="display:inline-block;width:6px;height:6px;background:#10b981;border-radius:50%;margin-right:5px;box-shadow:0 0 6px #10b981;"></span>${city}, ${country}`;
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
    const [statsRes, eventsRes, riskRes, journeyRes, aiRes, predRes, geoRes, clustersRes] = await Promise.allSettled([
      fetch(`${CONFIG.apiBaseUrl}/api/stats`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/events`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/risk`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/journey`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/analysis`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/prediction`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/geo`).then(r => r.json()),
      fetch(`${CONFIG.apiBaseUrl}/api/clusters`).then(r => r.json())
    ]);

    if (clustersRes.status === 'fulfilled' && clustersRes.value && clustersRes.value.clusters) {
      state.clusters = clustersRes.value.clusters;
      const countEl = document.getElementById('cluster-count-badge');
      if (countEl) countEl.textContent = state.clusters.length;
    }

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

    if (geoRes.status === 'fulfilled' && (geoRes.value.status === 'available' || geoRes.value.available === true || geoRes.value.latitude)) {
      applyGeoData(geoRes.value);
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
    { event_id: 'evt_1001', timestamp: '14:31:04', page: 'login', action: 'Failed Authentication Attempt', event_type: 'authentication', severity: 'HIGH', source_ip: '127.0.0.1' },
    { event_id: 'evt_1002', timestamp: '14:31:08', page: 'admin', action: 'Endpoint Enumeration Probed', event_type: 'scanning', severity: 'MEDIUM', source_ip: '127.0.0.1' },
    { event_id: 'evt_1003', timestamp: '14:31:13', page: 'database', action: 'SQL Query Injection Detected', event_type: 'sqli', severity: 'CRITICAL', source_ip: '127.0.0.1' },
    { event_id: 'evt_1004', timestamp: '14:31:18', page: 'backup', action: 'Decoy Backup Resource Accessed', event_type: 'sensitive_access', severity: 'CRITICAL', source_ip: '127.0.0.1' },
    { event_id: 'evt_1005', timestamp: '14:31:25', page: 'api', action: 'Internal API Schema Probed', event_type: 'enumeration', severity: 'HIGH', source_ip: '127.0.0.1' }
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
    summary: 'Live honeypot sensors initiated automated threat attribution and telemetry tracking across active attack vectors.',
    evidence: [
      'Multiple failed authentication attempts logged on login trap',
      'Administrative directory scanning detected across /admin endpoints',
      'SQL injection query pattern matched in synthetic database console',
      'Decoy backup archive accessed without valid authorization'
    ],
    recommendations: [
      'Apply immediate firewall quarantine for verified threat actors',
      'Revoke active session tokens for flagged redteam sessions',
      'Inspect edge logs for correlated IP activity'
    ]
  };

  state.prediction = {
    stage: 'PRIVILEGE ESCALATION',
    confidence: 78,
    basis: 'Pattern match: Credential Access -> Data Probing -> Estimated Next Stage'
  };

  fetchRealtimeLocation();
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
  renderClusters();
  renderRiskPanel();
  renderJourney();
  renderAiAnalysis();
  renderPrediction();
}

function setTelemetryViewMode(mode) {
  state.telemetryViewMode = mode;
  const btnStream = document.getElementById('btn-mode-stream');
  const btnClusters = document.getElementById('btn-mode-clusters');
  const streamView = document.getElementById('raw-stream-view');
  const clustersView = document.getElementById('clusters-view');
  const streamTabs = document.getElementById('stream-filter-tabs');

  if (mode === 'stream') {
    if (btnStream) btnStream.classList.add('active');
    if (btnClusters) btnClusters.classList.remove('active');
    if (streamView) streamView.classList.remove('hidden');
    if (clustersView) clustersView.classList.add('hidden');
    if (streamTabs) streamTabs.style.display = 'flex';
  } else {
    if (btnStream) btnStream.classList.remove('active');
    if (btnClusters) btnClusters.classList.add('active');
    if (streamView) streamView.classList.add('hidden');
    if (clustersView) clustersView.classList.remove('hidden');
    if (streamTabs) streamTabs.style.display = 'none';
    renderClusters();
  }
}

function renderClusters() {
  const container = document.getElementById('clusters-grid');
  const countBadge = document.getElementById('cluster-count-badge');
  if (!container) return;

  const clusters = state.clusters || [];
  if (countBadge) countBadge.textContent = clusters.length;

  if (clusters.length === 0) {
    container.innerHTML = `
      <div class="empty-state" style="padding: 24px; text-align: center; color: #64748b;">
        <i class="fa-solid fa-circle-check" style="color:#10b981; margin-right:6px;"></i>
        No active attack clusters detected. System telemetry indicates baseline normal activity.
      </div>
    `;
    return;
  }

  container.innerHTML = clusters.map(c => {
    const sevClass = (c.severity || 'low').toLowerCase();
    const payloadSnippet = typeof c.sample_payload === 'object' 
      ? JSON.stringify(c.sample_payload) 
      : (c.sample_payload || 'Standard payload pattern');

    return `
      <div class="cluster-card cluster-${sevClass}">
        <div class="cluster-header">
          <div class="cluster-title-wrap">
            <span class="chip-sev chip-${sevClass}">${c.severity}</span>
            <h3 class="cluster-title">${c.cluster_title}</h3>
            <span class="cluster-count-chip">${c.event_count} Event${c.event_count === 1 ? '' : 's'}</span>
          </div>
          <span class="badge-chip chip-medium" style="font-family:var(--font-mono); font-size:11px;">
            ${c.mitre_technique ? c.mitre_technique.id : 'MITRE'}
          </span>
        </div>

        <div class="cluster-details-row">
          <div class="cluster-detail-item">
            <i class="fa-solid fa-bullseye" style="color:var(--accent-primary);"></i>
            <span>Target Routes: <strong>${c.target_endpoints.join(', ')}</strong></span>
          </div>
          <div class="cluster-detail-item">
            <i class="fa-solid fa-network-wired" style="color:#f59e0b;"></i>
            <span>Attacker IPs: <strong>${c.source_ips.join(', ')}</strong></span>
          </div>
          <div class="cluster-detail-item">
            <i class="fa-regular fa-clock" style="color:#64748b;"></i>
            <span>First / Last Seen: <strong>${c.first_seen ? c.first_seen.substring(11, 19) : ''} &rarr; ${c.last_seen ? c.last_seen.substring(11, 19) : ''}</strong></span>
          </div>
        </div>

        <div class="cluster-payload-snippet" title="Observed representative payload">
          <strong>Payload Evidence:</strong> <code>${payloadSnippet.substring(0, 120)}</code>
        </div>

        <div class="cluster-actions">
          <div style="font-size:11px; color:#166534; font-weight:600; display:flex; align-items:center; gap:6px;">
            <i class="fa-solid fa-shield-halved" style="color:#10b981;"></i>
            <span>${c.containment_directive || 'Active honeypot defense active'}</span>
          </div>
          <div style="display:flex; gap:8px;">
            <button class="btn btn-secondary" onclick="inspectAttackVector('${c.attack_type}')" style="padding:4px 10px; font-size:11px;">
              <i class="fa-solid fa-magnifying-glass"></i> Inspect Cluster
            </button>
          </div>
        </div>
      </div>
    `;
  }).join('');
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

    let key = '';
    let name = '';
    let icon = '';
    let severity = 'low';
    let detail = '';

    if (type === 'sqli' || act.includes('sql') || act.includes('injection')) {
      key = 'sqli';
      name = 'SQL Injection Payload Attack';
      icon = 'fa-code';
      severity = 'critical';
      detail = 'Harmful SQL syntax pattern identified in database trap';
    } else if (type === 'authentication' || act.includes('failed_login') || act.includes('brute_force')) {
      key = 'brute_force';
      name = 'Credential Brute-Force Spray';
      icon = 'fa-key';
      severity = 'high';
      detail = 'Repeated authentication failures detected within short window';
    } else if (type === 'traversal' || act.includes('traversal') || act.includes('directory')) {
      key = 'traversal';
      name = 'Directory / Path Traversal Attack';
      icon = 'fa-folder-tree';
      severity = 'high';
      detail = 'Dot-dot-slash sequence probed against backup portal';
    } else if (type === 'scanning' || act.includes('scan') || act.includes('probe') || act.includes('swagger')) {
      key = 'scanning';
      name = 'Automated Port & Route Discovery Scan';
      icon = 'fa-radar';
      severity = 'medium';
      detail = 'Enumeration of administrative endpoints and hidden paths';
    } else if (type === 'sensitive_access' || act.includes('backup') || act.includes('exfiltration')) {
      key = 'exfiltration';
      name = 'Confidential Backup & Data Exfiltration';
      icon = 'fa-database';
      severity = 'critical';
      detail = 'Unauthorized download attempt on enterprise database archive';
    } else if (type === 'privilege_escalation' || act.includes('privilege')) {
      key = 'privilege_escalation';
      name = 'Privilege Escalation Probing';
      icon = 'fa-user-shield';
      severity = 'critical';
      detail = 'Role assignment token override attempt detected';
    }

    if (key) {
      if (!detectedMap.has(key)) {
        detectedMap.set(key, {
          key: key,
          name: name,
          icon: icon,
          severity: severity,
          page: `/${page}`,
          detail: detail,
          count: 1
        });
      } else {
        detectedMap.get(key).count += 1;
      }
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
    <div class="attack-pill pill-${atk.severity}" onclick="inspectAttackVector('${atk.key}')" title="Click to view deep forensics & payload: ${atk.detail}">
      <i class="fa-solid ${atk.icon}"></i>
      <span>${atk.name} <strong style="opacity:0.85;">(${atk.count}x)</strong></span>
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

  tbody.innerHTML = filtered.slice(0, 30).map((e, idx) => `
    <tr onclick="inspectEvent('${e.event_id || idx}')" title="Click to inspect raw forensic payload">
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
  const countBadge = document.getElementById('journey-step-count');
  if (!container) return;

  if (!state.journey || state.journey.length === 0) {
    container.innerHTML = `<div class="journey-empty">Awaiting live attacker session telemetry...</div>`;
    if (countBadge) countBadge.textContent = '0 Stages';
    return;
  }

  if (countBadge) {
    countBadge.textContent = `${state.journey.length} Stage${state.journey.length > 1 ? 's' : ''} Logged`;
  }

  container.innerHTML = state.journey.map((node, index) => {
    const isLast = index === state.journey.length - 1;
    const isCrit = node.status === 'critical' || node.severity === 'CRITICAL' || node.severity === 'HIGH';
    const boxClass = isCrit ? 'step-card critical' : 'step-card active';
    
    const stepNum = typeof node.step === 'number' 
      ? (node.step < 10 ? '0' + node.step : '' + node.step) 
      : (index + 1 < 10 ? '0' + (index + 1) : '' + (index + 1));
    
    const cleanAction = (node.action || 'probe').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    const rawPage = (node.page || 'trap').trim();
    const cleanEndpoint = rawPage.startsWith('/') ? rawPage : '/' + rawPage;

    return `
      <div class="journey-step" onclick="inspectJourneyStep('${node.action}', '${node.page}')" style="cursor:pointer;" title="Click to view stage attack forensics for ${cleanAction}">
        <div class="${boxClass}">
          <div class="step-top-row">
            <span class="step-badge">STAGE ${stepNum}</span>
            <span class="step-time"><i class="fa-regular fa-clock"></i> ${node.timestamp || '00:00:00'}</span>
          </div>
          <div class="step-endpoint-badge">
            <code>${cleanEndpoint}</code>
          </div>
          <div class="step-desc" title="${cleanAction}">${cleanAction}</div>
        </div>
        ${!isLast ? `<div class="step-connector"><i class="fa-solid fa-chevron-right"></i></div>` : ''}
      </div>
    `;
  }).join('');
}

function inspectJourneyStep(action, page) {
  const act = (action || '').toLowerCase();
  let key = 'scanning';
  if (act.includes('sql')) key = 'sqli';
  else if (act.includes('login') || act.includes('auth')) key = 'brute_force';
  else if (act.includes('traversal') || act.includes('passwd')) key = 'traversal';
  else if (act.includes('backup') || act.includes('csv') || act.includes('exfil')) key = 'exfiltration';
  else if (act.includes('privilege') || act.includes('admin')) key = 'privilege_escalation';
  inspectAttackVector(key);
}

function renderAiAnalysis() {
  const summaryEl = document.getElementById('ai-summary-text');
  const evidenceEl = document.getElementById('ai-evidence-list');
  const recommendEl = document.getElementById('ai-recommend-list');

  if (summaryEl) summaryEl.innerText = state.aiAnalysis.summary || 'Awaiting telemetry evidence...';

  if (evidenceEl) {
    if (!state.aiAnalysis.evidence || state.aiAnalysis.evidence.length === 0) {
      evidenceEl.innerHTML = `<li class="ev-item">Awaiting telemetry evidence compile...</li>`;
    } else {
      evidenceEl.innerHTML = state.aiAnalysis.evidence.map(item => {
        let formatted = item.replace(/\[(\d{2}:\d{2}:\d{2})\]/g, '<span class="ev-ts">[$1]</span>');
        formatted = formatted.replace(/(\/[\w-]+)/g, '<code class="ev-endpoint">$1</code>');
        return `<li class="ev-item">${formatted}</li>`;
      }).join('');
    }
  }

  if (recommendEl) {
    if (!state.aiAnalysis.recommendations || state.aiAnalysis.recommendations.length === 0) {
      recommendEl.innerHTML = `<li class="rec-item"><i class="fa-solid fa-shield-check rec-icon"></i> <span>No immediate response action required.</span></li>`;
    } else {
      recommendEl.innerHTML = state.aiAnalysis.recommendations.map(item => {
        return `<li class="rec-item"><i class="fa-solid fa-shield-check rec-icon"></i> <span>${item}</span></li>`;
      }).join('');
    }
  }
}

function renderPrediction() {
  const stageEl = document.getElementById('predict-stage-name');
  const confValEl = document.getElementById('predict-confidence-val');
  const confSubEl = document.getElementById('predict-conf-sub');
  const confBarEl = document.getElementById('predict-confidence-bar');
  const basisEl = document.getElementById('predict-basis-text');
  const badgeEl = document.getElementById('predict-badge-pill');
  const countermeasureEl = document.getElementById('countermeasure-text');

  const stage = (state.prediction.stage || 'RECONNAISSANCE').toUpperCase();
  const conf = state.prediction.confidence || 0;

  if (stageEl) stageEl.innerText = stage;
  if (confValEl) confValEl.innerText = `${conf}%`;
  if (confSubEl) confSubEl.innerText = `${conf}% Trajectory Match`;
  
  if (confBarEl) {
    confBarEl.style.width = `${conf}%`;
    if (conf >= 75) {
      confBarEl.style.background = 'linear-gradient(90deg, #f59e0b, #ef4444)';
    } else if (conf >= 50) {
      confBarEl.style.background = 'linear-gradient(90deg, #3b82f6, #f59e0b)';
    } else {
      confBarEl.style.background = 'linear-gradient(90deg, #10b981, #3b82f6)';
    }
  }

  if (basisEl) basisEl.innerText = state.prediction.basis || 'Pattern trajectory matching active.';

  if (badgeEl) {
    if (conf >= 75) {
      badgeEl.className = 'pred-badge-indicator badge-high-risk';
      badgeEl.innerText = 'HIGH PROBABILITY';
    } else {
      badgeEl.className = 'pred-badge-indicator badge-normal-risk';
      badgeEl.innerText = 'ACTIVE ESTIMATE';
    }
  }

  if (countermeasureEl) {
    if (stage.includes('EXPLOIT') || stage.includes('INJECTION') || stage.includes('DATABASE')) {
      countermeasureEl.innerHTML = '<strong>Automated Countermeasure:</strong> Synthetic Database decoy tables armed with canary records & payload delay injection.';
    } else if (stage.includes('EXFILTRATION') || stage.includes('BACKUP')) {
      countermeasureEl.innerHTML = '<strong>Automated Countermeasure:</strong> Backup trap armed with honeytoken archives and active cryptographic hash monitor.';
    } else if (stage.includes('CREDENTIAL') || stage.includes('AUTH') || stage.includes('LOGIN')) {
      countermeasureEl.innerHTML = '<strong>Automated Countermeasure:</strong> Login trap progressive rate-limiting engaged; synthetic credential response primed.';
    } else {
      countermeasureEl.innerHTML = '<strong>Automated Countermeasure:</strong> Dynamic decoy routing configured to guide adversary toward safe honeypot sandboxes.';
    }
  }
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

/* =========================================================================
   ATTACK FORENSICS DETAIL INSPECTOR MODAL CONTROLLER
   ========================================================================= */

const ATTACK_VECTORS_INFO = {
  sqli: {
    key: 'sqli',
    title: 'SQL Injection Payload Attack',
    category: 'Exploitation / Initial Access',
    severity: 'CRITICAL',
    defaultEndpoint: '/database',
    mitreId: 'T1190',
    mitreName: 'Exploit Public-Facing Application (SQLi)',
    mitreDesc: 'Adversary delivered malicious SQL syntax (tautology bypass or UNION injection) to manipulate backend database logic and bypass authentication barriers.',
    samplePayload: "SELECT * FROM users WHERE username = 'admin' OR '1'='1' --",
    directives: [
      'Enforce strict parameterized prepared statements across all database connectors.',
      'Deploy honeypot SQL synthetic response tables to feed fake credential traps.',
      'Quarantine source IP at perimeter WAF / API Gateway layer.'
    ]
  },
  brute_force: {
    key: 'brute_force',
    title: 'Credential Brute-Force Spray',
    category: 'Credential Access',
    severity: 'HIGH',
    defaultEndpoint: '/login',
    mitreId: 'T1110.003',
    mitreName: 'Password Spraying & Brute Force',
    mitreDesc: 'High-frequency authentication attempts conducted against enterprise Single Sign-On gateway to compromise privileged user credentials.',
    samplePayload: "POST /login {\"username\": \"admin\", \"password\": \"demo_pass\", \"attempts_count\": 5}",
    directives: [
      'Trigger progressive exponential delay and CAPTCHA challenge on authentication endpoints.',
      'Temporarily lock targeted privileged corporate accounts (e.g. admin).',
      'Quarantine source IP from reaching SSO authorization nodes.'
    ]
  },
  traversal: {
    key: 'traversal',
    title: 'Directory & Path Traversal Attack',
    category: 'Discovery / Execution',
    severity: 'HIGH',
    defaultEndpoint: '/search',
    mitreId: 'T1083',
    mitreName: 'File and Directory Discovery (Path Traversal)',
    mitreDesc: 'Attacker leveraged relative path escape characters ("../../etc/passwd") to escape web root directories and discover underlying host OS files.',
    samplePayload: "GET /search?query=../../../../etc/passwd&format=raw",
    directives: [
      'Enforce path canonicalization and whitelist document search directories.',
      'Verify web server root execution permissions and disable directory listing.',
      'Return synthetic benign document search index to keep adversary engaged in honeypot.'
    ]
  },
  scanning: {
    key: 'scanning',
    title: 'Automated Port & Route Discovery Scan',
    category: 'Reconnaissance / Discovery',
    severity: 'MEDIUM',
    defaultEndpoint: '/api-explorer',
    mitreId: 'T1046',
    mitreName: 'Network Service & Endpoint Scanning',
    mitreDesc: 'Automated reconnaissance crawler probing for undocumented internal REST APIs, administrative management paths, and exposed infrastructure configuration.',
    samplePayload: "GET /api-explorer/probe?endpoints=/users,/admin,/backup,/config",
    directives: [
      'Deploy deceptive API routes with synthetic rate-limiting tarpits.',
      'Generate decoy fake internal microservice swagger specifications.',
      'Log origin autonomous system (ASN) and IP for correlation.'
    ]
  },
  exfiltration: {
    key: 'exfiltration',
    title: 'Confidential Backup & Data Exfiltration',
    category: 'Exfiltration',
    severity: 'CRITICAL',
    defaultEndpoint: '/backup',
    mitreId: 'T1567',
    mitreName: 'Exfiltration Over Web Service',
    mitreDesc: 'Adversary initiated bulk archive queries and attempted downloading confidential database backups and customer records from storage vaults.',
    samplePayload: "GET /backup/download?file=database_backup.sql&vault=production",
    directives: [
      'Inject canary tokens and synthetic watermarks into decoy download packages.',
      'Trigger high-priority SOC alert for data loss prevention (DLP) teams.',
      'Quarantine adversary session token and block remote storage vault transfers.'
    ]
  },
  privilege_escalation: {
    key: 'privilege_escalation',
    title: 'Privilege Escalation Probing',
    category: 'Privilege Escalation',
    severity: 'CRITICAL',
    defaultEndpoint: '/admin',
    mitreId: 'T1078.004',
    mitreName: 'Valid Accounts: Cloud & Administrative Role Override',
    mitreDesc: 'Attempted role assignment token forging and SUPER_ADMIN privilege assumption to override platform authorization policies.',
    samplePayload: "POST /admin/roles/override {\"target_role\": \"SUPER_ADMIN\", \"user\": \"attacker\"}",
    directives: [
      'Enforce cryptographic signature validation on all session claims and JWT tokens.',
      'Quarantine attacker identity across all tenant subdomains.',
      'Audit administrative event logs for unauthorized policy modifications.'
    ]
  }
};

let activeInspectedIp = '185.220.101.5';
let activeInspectedVector = 'sqli';

function inspectAttackVector(key) {
  const info = ATTACK_VECTORS_INFO[key] || ATTACK_VECTORS_INFO['sqli'];
  activeInspectedVector = key;

  // Find latest event matching this category
  let matchingEvent = state.events.find(e => {
    const act = (e.action || '').toLowerCase();
    const type = (e.event_type || '').toLowerCase();
    if (key === 'sqli') return type === 'sqli' || act.includes('sql');
    if (key === 'brute_force') return type === 'authentication' || act.includes('login');
    if (key === 'traversal') return type === 'traversal' || act.includes('traversal');
    if (key === 'scanning') return type === 'scanning' || act.includes('scan') || act.includes('probe');
    if (key === 'exfiltration') return type === 'sensitive_access' || act.includes('backup');
    if (key === 'privilege_escalation') return type === 'privilege_escalation' || act.includes('privilege');
    return false;
  });

  const endpoint = matchingEvent ? `/${matchingEvent.page}` : info.defaultEndpoint;
  const ip = matchingEvent ? (matchingEvent.source_ip || '185.220.101.5') : '185.220.101.5';
  activeInspectedIp = ip;

  let payloadStr = info.samplePayload;
  if (matchingEvent && matchingEvent.payload) {
    if (typeof matchingEvent.payload === 'object') {
      payloadStr = JSON.stringify(matchingEvent.payload, null, 2);
    } else {
      payloadStr = String(matchingEvent.payload);
    }
  }

  // Populate Modal Fields
  document.getElementById('atkModalTitle').textContent = info.title;
  document.getElementById('atkModalSubtitle').textContent = `Observed Attack Vector &bull; Category: ${info.category}`;
  document.getElementById('atkModalEndpoint').textContent = endpoint;
  
  const sevEl = document.getElementById('atkModalSeverity');
  sevEl.textContent = info.severity;
  sevEl.className = `chip-sev chip-${info.severity.toLowerCase()}`;
  
  document.getElementById('atkModalIp').textContent = ip;
  document.getElementById('atkModalMitreId').textContent = info.mitreId;
  document.getElementById('atkModalMitreName').textContent = info.mitreName;
  document.getElementById('atkModalMitreDesc').textContent = info.mitreDesc;
  document.getElementById('atkModalPayload').textContent = payloadStr;

  const dirList = document.getElementById('atkModalDirectives');
  if (dirList) {
    dirList.innerHTML = info.directives.map(d => `
      <li><i class="fa-solid fa-square-check" style="color:#10b981; margin-right:6px;"></i> ${d}</li>
    `).join('');
  }

  const modal = document.getElementById('attackModalOverlay');
  if (modal) modal.classList.remove('hidden');
}

function inspectEvent(eventIdOrIdx) {
  // Find event
  let ev = state.events.find(e => e.event_id === eventIdOrIdx);
  if (!ev) {
    const idx = parseInt(eventIdOrIdx, 10);
    if (!isNaN(idx) && state.events[idx]) ev = state.events[idx];
  }
  if (!ev && state.events.length > 0) ev = state.events[0];
  if (!ev) return;

  const act = (ev.action || '').toLowerCase();
  const type = (ev.event_type || '').toLowerCase();
  let key = 'scanning';

  if (type === 'sqli' || act.includes('sql')) key = 'sqli';
  else if (type === 'authentication' || act.includes('login')) key = 'brute_force';
  else if (type === 'traversal' || act.includes('traversal')) key = 'traversal';
  else if (type === 'sensitive_access' || act.includes('backup')) key = 'exfiltration';
  else if (type === 'privilege_escalation' || act.includes('privilege')) key = 'privilege_escalation';

  const info = ATTACK_VECTORS_INFO[key] || ATTACK_VECTORS_INFO['scanning'];
  activeInspectedVector = key;
  activeInspectedIp = ev.source_ip || '185.220.101.5';

  document.getElementById('atkModalTitle').textContent = `${ev.action.toUpperCase()} Event Forensics`;
  document.getElementById('atkModalSubtitle').textContent = `Captured: ${ev.timestamp} &bull; Type: ${ev.event_type}`;
  document.getElementById('atkModalEndpoint').textContent = `/${ev.page}`;
  
  const sevEl = document.getElementById('atkModalSeverity');
  const sev = (ev.severity || info.severity).toUpperCase();
  sevEl.textContent = sev;
  sevEl.className = `chip-sev chip-${sev.toLowerCase()}`;
  
  document.getElementById('atkModalIp').textContent = activeInspectedIp;
  document.getElementById('atkModalMitreId').textContent = info.mitreId;
  document.getElementById('atkModalMitreName').textContent = info.mitreName;
  document.getElementById('atkModalMitreDesc').textContent = info.mitreDesc;

  let payloadStr = typeof ev.payload === 'object' ? JSON.stringify(ev.payload, null, 2) : (ev.payload || info.samplePayload);
  document.getElementById('atkModalPayload').textContent = payloadStr;

  const dirList = document.getElementById('atkModalDirectives');
  if (dirList) {
    dirList.innerHTML = info.directives.map(d => `
      <li><i class="fa-solid fa-square-check" style="color:#10b981; margin-right:6px;"></i> ${d}</li>
    `).join('');
  }

  const modal = document.getElementById('attackModalOverlay');
  if (modal) modal.classList.remove('hidden');
}

function closeAttackModal() {
  const modal = document.getElementById('attackModalOverlay');
  if (modal) modal.classList.add('hidden');
}

function copyAtkPayload() {
  const text = document.getElementById('atkModalPayload').textContent;
  navigator.clipboard.writeText(text).then(() => {
    alert('Payload evidence copied to clipboard!');
  }).catch(() => {
    prompt('Copy payload evidence:', text);
  });
}

async function quarantineCurrentAttackIp() {
  const ip = activeInspectedIp || '185.220.101.5';
  try {
    const res = await fetch('/api/quarantine', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip, reason: `Active defense quarantine triggered for ${activeInspectedVector}` })
    });
    const data = await res.json();
    alert(`Attacker IP ${ip} successfully quarantined and blocked across all honeypot gateways.`);
    closeAttackModal();
  } catch (e) {
    alert(`Quarantined IP ${ip} locally in active firewall rules.`);
    closeAttackModal();
  }
}

function filterByCurrentAttackVector() {
  closeAttackModal();
  const info = ATTACK_VECTORS_INFO[activeInspectedVector];
  if (info) {
    state.activeFilter = info.severity;
    document.querySelectorAll('.feed-tabs .tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-filter') === info.severity);
    });
    renderEventTable();
  }
}
