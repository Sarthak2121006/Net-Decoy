/**
 * NetDecoy - Deception Trap Event Logger (M4)
 * Silent, robust event collector client helper.
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

    // 1. Always store locally for offline/demo resilience
    try {
      const existing = JSON.parse(localStorage.getItem('netdecoy_events') || '[]');
      existing.push(event);
      localStorage.setItem('netdecoy_events', JSON.stringify(existing));
      // Dispatch custom DOM event for live local listening if needed
      window.dispatchEvent(new CustomEvent('netdecoy_event_logged', { detail: event }));
    } catch (e) {
      // Silent catch
    }

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
    window.NetDecoySessionId = newId;
    return newId;
  };
})();
