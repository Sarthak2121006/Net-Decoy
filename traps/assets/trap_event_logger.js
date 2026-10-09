/**
 * NetDecoy - Deception Trap Event Logger (M4 Enhanced)
 * Silent, robust event collector client helper with live session telemetry widget.
 */

(function () {
  // Ensure a persistent session ID across page navigations in this tab
  let sessionId = sessionStorage.getItem('netdecoy_session_id');
  if (!sessionId) {
    sessionId = 'sess_' + Math.random().toString(36).substring(2, 9) + '_' + Date.now().toString(36);
    sessionStorage.setItem('netdecoy_session_id', sessionId);
  }

  window.NetDecoySessionId = sessionId;

  /**
   * Log an event silently to the NetDecoy Event Collector backend & local storage fallback.
   * @param {Object} eventData - { page, action, event_type, payload }
   */
  window.logDecoyEvent = async function ({ page, action, event_type, payload = {} }) {
    const event = {
      event_id: 'evt_' + Math.random().toString(36).substring(2, 10),
      session_id: window.NetDecoySessionId,
      timestamp: new Date().toISOString(),
      source_ip: '127.0.0.1', // populated by backend
      page: page,
      action: action,
      event_type: event_type,
      payload: payload
    };

    let count = 0;

    // 1. Always store locally for offline/demo resilience
    try {
      const existing = JSON.parse(localStorage.getItem('netdecoy_events') || '[]');
      existing.push(event);
      localStorage.setItem('netdecoy_events', JSON.stringify(existing));
      count = existing.length;

      // Dispatch custom DOM event for live local listening
      window.dispatchEvent(new CustomEvent('netdecoy_event_logged', { detail: event }));
    } catch (e) {
      // Silent catch
    }

    // Update floating telemetry bar
    updateTelemetryWidget(action, count);

    // 2. Transmit to Central Event Collector API
    try {
      await fetch('/api/events', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event)
      });
    } catch (err) {
      // Silent logging - never expose trap alert to potential attacker
      console.debug('[NetDecoy Silent Telemetry Captured]', event.action);
    }

    return event;
  };

  // Helper to clear session for fresh demo runs
  window.resetDecoySession = function () {
    const newId = 'sess_' + Math.random().toString(36).substring(2, 9) + '_' + Date.now().toString(36);
    sessionStorage.setItem('netdecoy_session_id', newId);
    sessionStorage.removeItem('decoy_failed_logins');
    window.NetDecoySessionId = newId;
    updateTelemetryWidget('session_reset', 0);
    return newId;
  };

  function updateTelemetryWidget(lastAction = 'ready', count = null) {
    const actionElem = document.getElementById('telemetryLastAction');
    const countElem = document.getElementById('telemetryCount');
    const sessElem = document.getElementById('telemetrySessId');

    if (count === null) {
      try {
        const existing = JSON.parse(localStorage.getItem('netdecoy_events') || '[]');
        count = existing.length;
      } catch(e) { count = 0; }
    }

    if (actionElem) actionElem.textContent = lastAction;
    if (countElem) countElem.textContent = count;
    if (sessElem) sessElem.textContent = window.NetDecoySessionId;
  }

  // Inject Floating Telemetry Bar into page on DOM load
  document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('netdecoyTelemetryWidget')) return;

    const widget = document.createElement('div');
    widget.id = 'netdecoyTelemetryWidget';
    widget.className = 'telemetry-bar';
    widget.innerHTML = `
      <div class="telemetry-status">
        <span class="pulse-dot"></span>
        <span>NetDecoy Telemetry Engine: <strong style="color:#fff;">Active</strong></span>
        <span style="opacity: 0.4;">|</span>
        <span>Session: <code id="telemetrySessId" style="color:#38bdf8;">${window.NetDecoySessionId}</code></span>
      </div>
      <div class="telemetry-status">
        <span>Captured Events: <span id="telemetryCount" class="telemetry-counter">0</span></span>
        <span style="opacity: 0.4;">|</span>
        <span>Last Action: <code id="telemetryLastAction" style="color:#f59e0b;">initialized</code></span>
        <button onclick="resetDecoySession()" style="background:rgba(255,255,255,0.08); border:1px solid #334155; color:#94a3b8; border-radius:4px; padding:2px 8px; font-size:0.75rem; cursor:pointer; margin-left:8px;">Reset Session</button>
      </div>
    `;
    document.body.appendChild(widget);
    updateTelemetryWidget('ready');
  });
})();
