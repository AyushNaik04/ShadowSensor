"""SQLAlchemy engine, session factory, and database initialization for ShadowSensor."""

from __future__ import annotations

import os
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)

# Database lives on the local filesystem — NOT the VMware shared
# folder. SQLite requires local NTFS file locking which VMware
# shared folders (\\vmware-host\Shared Folders\...) do not support.
# Override via SHADOWSENSOR_DB_DIR environment variable if needed.
_DEFAULT_DB_DIR = r"C:\ShadowSensor\data"
DB_DIR = Path(os.environ.get("SHADOWSENSOR_DB_DIR", _DEFAULT_DB_DIR))
DB_PATH = DB_DIR / "shadowsensor.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


def create_db_engine():
    """Create and configure the SQLite engine for ShadowSensor."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        echo=False,
    )

    @sa_event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_conn, _record) -> None:
        """
        Apply SQLite connection pragmas.
        All pragmas are wrapped defensively — VMware shared folder
        filesystems reject pragma operations with disk I/O errors.
        Failures are logged as warnings and silently skipped so the
        DB remains usable with SQLite defaults.
        """
        pragmas = [
            ("journal_mode", "WAL"),
            ("foreign_keys", "ON"),
            ("synchronous", "NORMAL"),
            ("busy_timeout", "5000"),
        ]
        cursor = dbapi_conn.cursor()
        for pragma_name, pragma_value in pragmas:
            try:
                cursor.execute(f"PRAGMA {pragma_name}={pragma_value}")
            except Exception as exc:  # noqa: BLE001
                import logging
                logging.getLogger(__name__).warning(
                    "PRAGMA %s=%s failed (filesystem may not support it): %s",
                    pragma_name, pragma_value, exc
                )
        cursor.close()

    return engine


engine = create_db_engine()
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Yield a committed-or-rolled-back SQLAlchemy session."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create all storage tables. Safe to call multiple times."""
    from storage.models import AlertRecord, EventRecord, ModelScoreRecord, RuleHitRecord  # noqa: F401

    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized at %s", DB_PATH)
