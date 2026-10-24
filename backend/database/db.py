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
    custom = os.getenv("NETDECOY_DB_URI")
    if custom:
        return custom

    is_serverless = any([
        os.getenv("VERCEL"),
        os.getenv("VERCEL_ENV"),
        os.getenv("AWS_LAMBDA_FUNCTION_NAME"),
        os.getenv("LAMBDA_TASK_ROOT"),
    ])

    if is_serverless:
        tmp_dir = tempfile.gettempdir()
        db_file = os.path.join(tmp_dir, "netdecoy.db").replace("\\", "/")
        if not db_file.startswith("/"):
            return f"sqlite:///{db_file}"
        return f"sqlite://{db_file}"

    local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netdecoy.db").replace("\\", "/")
    if not local_path.startswith("/"):
        return f"sqlite:///{local_path}"
    return f"sqlite://{local_path}"

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
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
