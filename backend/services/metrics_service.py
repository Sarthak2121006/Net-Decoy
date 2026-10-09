"""
Metrics and Analytics Aggregator for NetDecoy
Provides event velocity, top target traps, top attacking IPs, and severity distributions.
"""
from sqlalchemy import func
from backend.database.db import SessionLocal
from backend.database.models import EventModel, SessionModel

def get_telemetry_metrics() -> dict:
    """
    Compute comprehensive telemetry breakdown for SOC visualizations.
    """
    db = SessionLocal()
    try:
        # Top targeted trap pages
        top_traps_query = db.query(
            EventModel.page,
            func.count(EventModel.id).label("count")
        ).group_by(EventModel.page).order_by(func.count(EventModel.id).desc()).limit(6).all()
        top_traps = [{"page": p, "count": c} for p, c in top_traps_query]

        # Top source IPs
        top_ips_query = db.query(
            EventModel.source_ip,
            func.count(EventModel.id).label("count")
        ).group_by(EventModel.source_ip).order_by(func.count(EventModel.id).desc()).limit(5).all()
        top_ips = [{"ip": ip, "count": c} for ip, c in top_ips_query]

        # Severity breakdown
        severity_query = db.query(
            EventModel.severity,
            func.count(EventModel.id).label("count")
        ).group_by(EventModel.severity).all()
        severity_dist = {s: c for s, c in severity_query}

        # Event Type breakdown
        event_types_query = db.query(
            EventModel.event_type,
            func.count(EventModel.id).label("count")
        ).group_by(EventModel.event_type).all()
        event_type_dist = {et: c for et, c in event_types_query}

        return {
            "top_traps": top_traps,
            "top_ips": top_ips,
            "severity_distribution": severity_dist,
            "event_type_distribution": event_type_dist
        }
    finally:
        db.close()
