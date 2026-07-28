"""Proof tests for Fix 2 (Issues #2/#3): write failures visible, non-fatal."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from alerting.alert_manager import AlertManager
from normalizer.models import ProcessCreateEvent
from scripts.run_pipeline import handle_persist_pipeline_event
from storage import database as storage_database
from storage.models import EventRecord
from storage.storage_writer import StorageWriter


@pytest.fixture()
def in_memory_db(monkeypatch: pytest.MonkeyPatch):
    """Patch storage.database to use one shared in-memory SQLite database."""
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    test_session_local = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)

    monkeypatch.setattr(storage_database, "engine", test_engine)
    monkeypatch.setattr(storage_database, "SessionLocal", test_session_local)

    import storage.storage_writer as storage_writer_mod

    monkeypatch.setattr(storage_writer_mod, "get_session", storage_database.get_session)

    storage_database.init_db()
    yield test_engine, test_session_local
    test_engine.dispose()


def _benign_event() -> ProcessCreateEvent:
    return ProcessCreateEvent(
        event_id=1,
        utc_time=datetime.now(UTC).isoformat(),
        computer="test-host",
        process_guid="{fix2-visibility-001}",
        process_id=5252,
        image=r"C:\Windows\System32\notepad.exe",
        command_line="notepad.exe",
        current_directory=r"C:\Windows\System32",
        user="LAB\\tester",
        parent_process_id=100,
        parent_image=r"C:\Windows\explorer.exe",
        parent_command_line="explorer.exe",
        integrity_level="Medium",
        hashes=None,
    )


def test_write_failure_is_logged_visibly_without_raising(
    in_memory_db,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Fix 2 proof: forced write failure is logged with type/message; does not raise."""
    _, session_local = in_memory_db
    writer = StorageWriter()
    alert_manager = AlertManager(writer)

    @contextmanager
    def _broken_session():
        raise RuntimeError("DIAG_TEMP_INJECTED_SESSION_FAILURE_FOR_FIX2")
        yield

    import storage.storage_writer as storage_writer_mod

    monkeypatch.setattr(storage_writer_mod, "get_session", _broken_session)

    with caplog.at_level(logging.ERROR):
        ok = handle_persist_pipeline_event(
            _benign_event(),
            hits=[],
            storage_writer=writer,
            alert_manager=alert_manager,
        )

    assert ok is False
    assert "SQLite persistence failed (non-fatal)" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "DIAG_TEMP_INJECTED_SESSION_FAILURE_FOR_FIX2" in caplog.text
    # Traceback must be present (exc_info=True) — not a bare one-line warning.
    assert "Traceback" in caplog.text
    with session_local() as session:
        assert session.query(EventRecord).count() == 0


def test_pipeline_continues_after_logged_write_failure(
    in_memory_db,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After a failed write, a subsequent healthy persist still succeeds (non-fatal)."""
    _, session_local = in_memory_db
    writer = StorageWriter()
    alert_manager = AlertManager(writer)

    import storage.storage_writer as storage_writer_mod

    real_get_session = storage_writer_mod.get_session

    @contextmanager
    def _broken_session():
        raise RuntimeError("transient failure")
        yield

    monkeypatch.setattr(storage_writer_mod, "get_session", _broken_session)
    assert (
        handle_persist_pipeline_event(
            _benign_event(), hits=[], storage_writer=writer, alert_manager=alert_manager
        )
        is False
    )

    monkeypatch.setattr(storage_writer_mod, "get_session", real_get_session)
    assert (
        handle_persist_pipeline_event(
            _benign_event(), hits=[], storage_writer=writer, alert_manager=alert_manager
        )
        is True
    )
    with session_local() as session:
        assert session.query(EventRecord).count() == 1
