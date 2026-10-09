"""
Database connection and session lifecycle management
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from backend.database.models import Base

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netdecoy.db")
DATABASE_URI = os.getenv("NETDECOY_DB_URI", f"sqlite:///{DEFAULT_DB_PATH}")

engine = create_engine(
    DATABASE_URI,
    connect_args={"check_same_thread": False} if DATABASE_URI.startswith("sqlite") else {},
    echo=False
)

SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

def init_db():
    """Create all tables in the database."""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Yield a database session with automatic closure."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def reset_db():
    """Drop and recreate all tables for a clean demo state."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
