"""
Geolocation Service for NetDecoy
Enriches IP addresses with geographical coordinates, city, and country.
Never crashes or blocks on network failures.
"""
import requests
import ipaddress
import logging

logger = logging.getLogger(__name__)

# Cache resolved IPs in memory to reduce external lookups
_GEO_CACHE = {}

# Demo location pool for local/private test IPs during hackathon live testing
_DEMO_LOCATIONS = [
    {"city": "Mumbai", "country": "India", "country_code": "IN", "latitude": 19.0760, "longitude": 72.8777, "isp": "Demo Telecom Lab"},
    {"city": "Frankfurt", "country": "Germany", "country_code": "DE", "latitude": 50.1109, "longitude": 8.6821, "isp": "Honeynet Cloud Node"},
    {"city": "San Jose", "country": "United States", "country_code": "US", "latitude": 37.3382, "longitude": -121.8863, "isp": "Silicon Valley Cloud"},
    {"city": "Singapore", "country": "Singapore", "country_code": "SG", "latitude": 1.3521, "longitude": 103.8198, "isp": "AsiaPac Fiber"},
    {"city": "Tokyo", "country": "Japan", "country_code": "JP", "latitude": 35.6762, "longitude": 139.6503, "isp": "East Asia Transit"}
]

def is_private_or_loopback(ip_str: str) -> bool:
    """Check if an IP address is loopback, link-local, or private."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return True

def get_ip_geo(ip_str: str) -> dict:
    """
    Resolve IP to geographic details.
    Guaranteed to return a valid dict with 'available' boolean, never throws.
    """
    if not ip_str or not isinstance(ip_str, str):
        return {"available": False, "message": "Location unavailable"}

    ip_clean = ip_str.strip()
    if ip_clean in _GEO_CACHE:
        return _GEO_CACHE[ip_clean]

    # Handle loopback / private IPs gracefully with deterministic demo geo
    if is_private_or_loopback(ip_clean):
        # Pick deterministic demo location based on IP hash
        idx = hash(ip_clean) % len(_DEMO_LOCATIONS)
        demo_geo = _DEMO_LOCATIONS[idx].copy()
        demo_geo["available"] = True
        demo_geo["ip"] = ip_clean
        demo_geo["is_mock"] = True
        _GEO_CACHE[ip_clean] = demo_geo
        return demo_geo

    # For public IPs, attempt fast lookup with 2.0s strict timeout
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_clean}?fields=status,message,country,countryCode,city,lat,lon,isp",
            timeout=2.0
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                geo_info = {
                    "available": True,
                    "ip": ip_clean,
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "XX"),
                    "latitude": data.get("lat", 0.0),
                    "longitude": data.get("lon", 0.0),
                    "isp": data.get("isp", "Unknown ISP")
                }
                _GEO_CACHE[ip_clean] = geo_info
                return geo_info
    except Exception as e:
        logger.warning(f"Geo lookup failed for {ip_clean}: {e}")

    # Fallback response on failure
    fallback = {
        "available": False,
        "message": "Location unavailable",
        "ip": ip_clean
    }
    return fallback

def clear_geo_cache():
    """Clear in-memory geo cache on reset."""
    _GEO_CACHE.clear()
