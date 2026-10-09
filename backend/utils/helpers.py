"""
Utility helpers for NetDecoy Backend
"""
import datetime
import uuid
import re

def generate_event_id() -> str:
    """Generate a unique event ID with prefix and timestamp."""
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    rand_suffix = uuid.uuid4().hex[:6]
    return f"evt_{now_ts}_{rand_suffix}"

def generate_session_id() -> str:
    """Generate a random session ID if none is supplied."""
    rand_suffix = uuid.uuid4().hex[:8]
    return f"sess_{rand_suffix}"

def current_utc_iso() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sanitize_ip(ip: str) -> str:
    """Normalize and clean IP string."""
    if not ip or not isinstance(ip, str):
        return "127.0.0.1"
    ip = ip.strip()
    # If IPv6 mapped IPv4 e.g. ::ffff:127.0.0.1
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip
