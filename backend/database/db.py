"""
Database connection and session lifecycle management
"""
import os
import tempfile
import logging
from sqlalchemy import create_engine
from sqlalchemy.engine.url import URL
from sqlalchemy.pool import StaticPool
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
        db_file = os.path.abspath(os.path.join(tmp_dir, "netdecoy.db"))
        return URL.create(drivername="sqlite", database=db_file).render_as_string(hide_password=False)

    local_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "netdecoy.db"))
    return URL.create(drivername="sqlite", database=local_path).render_as_string(hide_password=False)


DATABASE_URI = _get_database_uri()


def _create_engine():
    global DATABASE_URI
    try:
        eng = create_engine(
            DATABASE_URI,
            connect_args={"check_same_thread": False} if DATABASE_URI.startswith("sqlite") else {},
            echo=False
        )
        with eng.connect():
            pass
        return eng
    except Exception as e:
        logger.warning(f"Could not connect to database {DATABASE_URI}: {e}. Falling back to in-memory SQLite.")
        DATABASE_URI = "sqlite:///:memory:"
        return create_engine(
            DATABASE_URI,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False
        )


engine = _create_engine()
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
