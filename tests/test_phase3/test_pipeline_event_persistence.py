"""Proof test for Fix 1 (Issue #1): zero-hit events still persist to events."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from alerting.alert_manager import AlertManager
from normalizer.models import ProcessCreateEvent
from rules.schema import RuleHit
from scripts.run_pipeline import persist_pipeline_event
from storage import database as storage_database
from storage.models import AlertRecord, EventRecord, RuleHitRecord
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
    # StorageWriter imports get_session at module level — rebind it too.
    import storage.storage_writer as storage_writer_mod

    monkeypatch.setattr(storage_writer_mod, "get_session", storage_database.get_session)

    storage_database.init_db()
    yield test_engine, test_session_local
    test_engine.dispose()


def _benign_notepad_event() -> ProcessCreateEvent:
    """Benign ProcessCreate that should not match offensive rules in isolation."""
    return ProcessCreateEvent(
        event_id=1,
        utc_time=datetime.now(UTC).isoformat(),
        computer="test-host",
        process_guid="{benign-zero-hit-001}",
        process_id=4242,
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


def _mock_hit(event: ProcessCreateEvent) -> RuleHit:
    return RuleHit(
        rule_id="PS_TEST_001",
        rule_name="Test PowerShell Rule",
        mitre_technique="T1059.001",
        mitre_tactic="Execution",
        severity="High",
        event_id=event.event_id,
        fired_at=datetime.now(UTC).isoformat(),
        matched_event=event,
    )


def test_zero_hit_event_still_writes_events_row(in_memory_db) -> None:
    """Fix 1 proof: empty hits must still create an events row (Issue #1)."""
    _, session_local = in_memory_db
    writer = StorageWriter()
    alert_manager = AlertManager(writer)
    event = _benign_notepad_event()

    event_db_id = persist_pipeline_event(event, hits=[], storage_writer=writer, alert_manager=alert_manager)

    assert isinstance(event_db_id, int)
    assert event_db_id > 0
    with session_local() as session:
        assert session.query(EventRecord).count() == 1
        assert session.query(RuleHitRecord).count() == 0
        assert session.query(AlertRecord).count() == 0
        row = session.query(EventRecord).one()
        assert row.id == event_db_id
        assert row.image == r"C:\Windows\System32\notepad.exe"


def test_nonempty_hits_still_write_event_and_rule_hit(in_memory_db) -> None:
    """Regression guard: hit path still persists event + rule_hit + alert."""
    _, session_local = in_memory_db
    writer = StorageWriter()
    alert_manager = AlertManager(writer)
    event = _benign_notepad_event()
    hits = [_mock_hit(event)]

    event_db_id = persist_pipeline_event(event, hits=hits, storage_writer=writer, alert_manager=alert_manager)

    assert isinstance(event_db_id, int)
    with session_local() as session:
        assert session.query(EventRecord).count() == 1
        assert session.query(RuleHitRecord).count() == 1
        assert session.query(AlertRecord).count() == 1
