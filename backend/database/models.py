"""
Database models for NetDecoy SQLite storage
"""
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Text, DateTime
import json

Base = declarative_base()

class EventModel(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    session_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(String(64), nullable=False, index=True)
    source_ip = Column(String(64), nullable=False, index=True)
    page = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    event_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(16), nullable=False, default="LOW", index=True)
    payload_json = Column(Text, nullable=False, default="{}")
    geo_json = Column(Text, nullable=True, default="{}")

    def to_dict(self):
        """Serialize event to contract dictionary."""
        try:
            payload = json.loads(self.payload_json) if self.payload_json else {}
        except Exception:
            payload = {}
            
        try:
            geo = json.loads(self.geo_json) if self.geo_json else {}
        except Exception:
            geo = {}

        return {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "page": self.page,
            "action": self.action,
            "event_type": self.event_type,
            "severity": self.severity,
            "payload": payload,
            "geo": geo
        }


class SessionModel(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    source_ip = Column(String(64), nullable=False)
    first_seen = Column(String(64), nullable=False)
    last_seen = Column(String(64), nullable=False)
    event_count = Column(Integer, nullable=False, default=1)
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(16), nullable=False, default="LOW")
    status = Column(String(32), nullable=False, default="active")

    def to_dict(self):
        """Serialize session to dictionary."""
        return {
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "status": self.status
        }


class QuarantineModel(Base):
    __tablename__ = "quarantined_ips"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(64), unique=True, nullable=False, index=True)
    reason = Column(String(255), nullable=False, default="Automated High Risk Containment")
    quarantined_at = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="active")

    def to_dict(self):
        """Serialize quarantine record."""
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "quarantined_at": self.quarantined_at,
            "status": self.status
        }
