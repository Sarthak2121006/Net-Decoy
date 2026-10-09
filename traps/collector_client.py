"""
NetDecoy Trap Collector Client Helper
Enables any trap page to emit honeypot telemetry with minimal boilerplate.
"""
import requests
import logging

logger = logging.getLogger("netdecoy.traps")

class TrapCollectorClient:
    def __init__(self, backend_url: str = "http://localhost:5000", trap_name: str = "general_trap"):
        self.backend_url = backend_url.rstrip("/")
        self.trap_name = trap_name

    def emit_event(
        self,
        session_id: str,
        source_ip: str,
        action: str,
        event_type: str = "reconnaissance",
        payload: dict = None,
        severity: str = None
    ) -> dict:
        """Send an event via HTTP to the backend collector."""
        endpoint = f"{self.backend_url}/api/events"
        data = {
            "session_id": session_id,
            "source_ip": source_ip,
            "page": self.trap_name,
            "action": action,
            "event_type": event_type,
            "payload": payload or {},
            "severity": severity
        }
        try:
            res = requests.post(endpoint, json=data, timeout=3.0)
            if res.status_code == 201:
                return res.json()
        except Exception as e:
            logger.warning(f"Failed to emit trap event over HTTP: {e}")

        # Fallback to direct python collector if in same process
        try:
            from backend.services.collector import log_event
            return {
                "status": "success",
                "event": log_event(
                    session_id=session_id,
                    source_ip=source_ip,
                    page=self.trap_name,
                    action=action,
                    event_type=event_type,
                    payload=payload,
                    severity=severity
                )
            }
        except Exception as local_err:
            logger.error(f"Local collector fallback failed: {local_err}")
            return {"status": "error", "message": "Failed to log event"}
