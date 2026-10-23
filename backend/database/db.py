"""
Database connection and session lifecycle management
"""
import os
import tempfile
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from backend.database.models import Base

logger = logging.getLogger(__name__)

def _get_database_uri():
    custom_uri = os.getenv("NETDECOY_DB_URI")
    if custom_uri:
        return custom_uri

    local_dir = os.path.dirname(os.path.abspath(__file__))
    is_serverless = any([
        os.getenv("VERCEL"),
        os.getenv("VERCEL_ENV"),
        os.getenv("AWS_LAMBDA_FUNCTION_NAME"),
        os.getenv("LAMBDA_TASK_ROOT"),
        not os.access(local_dir, os.W_OK)
    ])

    if is_serverless:
        tmp_dir = tempfile.gettempdir()
        db_path = os.path.join(tmp_dir, "netdecoy.db")
        return f"sqlite:///{db_path}"

    return f"sqlite:///{os.path.join(local_dir, 'netdecoy.db')}"

DATABASE_URI = _get_database_uri()

engine = create_engine(
    DATABASE_URI,
    connect_args={"check_same_thread": False} if DATABASE_URI.startswith("sqlite") else {},
    echo=False
)

SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

def init_db():
    """Create all tables in the database safely."""
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        logger.warning(f"Database table init non-fatal warning: {e}")

def get_db():
    """Yield a database session with automatic closure."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def reset_db():
    """Drop and recreate all tables for a clean demo state."""
    try:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        logger.warning(f"Database reset non-fatal warning: {e}")
