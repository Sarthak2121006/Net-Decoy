"""
Quarantine & Active Defense Service for NetDecoy
Manages automated or manual IP containment rules.
"""
from backend.database.db import SessionLocal
from backend.database.models import QuarantineModel
from backend.utils.helpers import current_utc_iso, sanitize_ip
import logging

logger = logging.getLogger(__name__)

def is_ip_quarantined(ip_address: str) -> bool:
    """Check if an IP address is actively blocked/quarantined."""
    clean_ip = sanitize_ip(ip_address)
    db = SessionLocal()
    try:
        record = db.query(QuarantineModel).filter(
            QuarantineModel.ip_address == clean_ip,
            QuarantineModel.status == "active"
        ).first()
        return record is not None
    finally:
        db.close()

def quarantine_ip(ip_address: str, reason: str = None) -> dict:
    """Add an IP address to the active quarantine blocklist."""
    clean_ip = sanitize_ip(ip_address)
    ts = current_utc_iso()
    default_reason = reason or "Manual Analyst Quarantine"

    db = SessionLocal()
    try:
        record = db.query(QuarantineModel).filter(QuarantineModel.ip_address == clean_ip).first()
        if record:
            record.status = "active"
            record.reason = default_reason
            record.quarantined_at = ts
            db.commit()
            return record.to_dict()
        else:
            new_record = QuarantineModel(
                ip_address=clean_ip,
                reason=default_reason,
                quarantined_at=ts,
                status="active"
            )
            db.add(new_record)
            db.commit()
            return new_record.to_dict()
    except Exception as e:
        db.rollback()
        logger.error(f"Error quarantining IP {clean_ip}: {e}")
        return {"ip_address": clean_ip, "status": "active", "reason": default_reason, "quarantined_at": ts}
    finally:
        db.close()

def unquarantine_ip(ip_address: str) -> bool:
    """Remove or release an IP address from active quarantine."""
    clean_ip = sanitize_ip(ip_address)
    db = SessionLocal()
    try:
        record = db.query(QuarantineModel).filter(QuarantineModel.ip_address == clean_ip).first()
        if record:
            db.delete(record)
            db.commit()
            return True
        return False
    except Exception as e:
        db.rollback()
        logger.error(f"Error unquarantining IP {clean_ip}: {e}")
        return False
    finally:
        db.close()

def list_quarantined_ips() -> list:
    """Retrieve all actively quarantined IPs."""
    db = SessionLocal()
    try:
        records = db.query(QuarantineModel).filter(QuarantineModel.status == "active").all()
        return [r.to_dict() for r in records]
    finally:
        db.close()
