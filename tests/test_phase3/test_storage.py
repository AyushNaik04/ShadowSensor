"""Unit tests for Phase 3 storage initialization and writers."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from normalizer.models import ProcessCreateEvent
from rules.schema import RuleHit
from storage import database as storage_database
from storage.models import AlertRecord, EventRecord, ModelScoreRecord, RuleHitRecord
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

    storage_database.init_db()
    yield test_engine, test_session_local
    test_engine.dispose()


def _mock_event() -> ProcessCreateEvent:
    """Create a valid normalized ProcessCreate event for tests."""
    return ProcessCreateEvent(
        event_id=1,
        utc_time=datetime.now(UTC).isoformat(),
        computer="test-host",
        process_guid="{abc-123}",
        process_id=4321,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell -NoProfile",
        current_directory=r"C:\Windows\System32",
        user="LAB\\tester",
        parent_process_id=100,
        parent_image=r"C:\Windows\explorer.exe",
        parent_command_line="explorer.exe",
        integrity_level="High",
        hashes=None,
    )


def _mock_hit(event: ProcessCreateEvent) -> RuleHit:
    """Create a valid RuleHit for tests."""
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


def test_init_db_creates_all_tables(in_memory_db) -> None:
    engine, _ = in_memory_db
    table_names = set(inspect(engine).get_table_names())
    assert {"events", "rule_hits", "alerts", "model_scores"}.issubset(table_names)


def test_model_scores_table_exists_and_is_empty_after_init(in_memory_db) -> None:
    _, session_local = in_memory_db
    with session_local() as session:
        assert session.query(ModelScoreRecord).count() == 0


def test_write_event_valid_returns_positive_id(in_memory_db) -> None:
    writer = StorageWriter()
    event_id = writer.write_event(_mock_event())
    assert isinstance(event_id, int)
    assert event_id > 0


def test_write_event_with_garbage_object_returns_none(in_memory_db) -> None:
    writer = StorageWriter()
    assert writer.write_event(object()) is None


def test_events_row_count_is_one_after_single_write(in_memory_db) -> None:
    _, session_local = in_memory_db
    writer = StorageWriter()
    writer.write_event(_mock_event())
    with session_local() as session:
        assert session.query(EventRecord).count() == 1


def test_write_rule_hit_valid_returns_positive_id(in_memory_db) -> None:
    writer = StorageWriter()
    event = _mock_event()
    event_id = writer.write_event(event)
    hit_id = writer.write_rule_hit(_mock_hit(event), event_id)
    assert isinstance(hit_id, int)
    assert hit_id > 0


def test_write_rule_hit_with_nullable_event_fk(in_memory_db) -> None:
    writer = StorageWriter()
    hit_id = writer.write_rule_hit(_mock_hit(_mock_event()), event_id=None)
    assert isinstance(hit_id, int)
    assert hit_id > 0


def test_inserted_rule_hit_has_expected_severity(in_memory_db) -> None:
    _, session_local = in_memory_db
    writer = StorageWriter()
    event = _mock_event()
    event_id = writer.write_event(event)
    writer.write_rule_hit(_mock_hit(event), event_id)
    with session_local() as session:
        stored = session.query(RuleHitRecord).first()
        assert stored is not None
        assert stored.severity == "High"


def test_write_alert_from_hit_sets_status_open(in_memory_db) -> None:
    _, session_local = in_memory_db
    writer = StorageWriter()
    event = _mock_event()
    event_id = writer.write_event(event)
    hit = _mock_hit(event)
    hit_id = writer.write_rule_hit(hit, event_id)
    writer.write_alert_from_hit(hit, hit_id, event_id, event)
    with session_local() as session:
        alert = session.query(AlertRecord).first()
        assert alert is not None
        assert alert.status == "open"


def test_alert_suspected_families_is_none(in_memory_db) -> None:
    _, session_local = in_memory_db
    writer = StorageWriter()
    event = _mock_event()
    event_id = writer.write_event(event)
    hit = _mock_hit(event)
    hit_id = writer.write_rule_hit(hit, event_id)
    writer.write_alert_from_hit(hit, hit_id, event_id, event)
    with session_local() as session:
        alert = session.query(AlertRecord).first()
        assert alert is not None
        assert alert.suspected_families is None


def test_full_cycle_inserts_one_row_each(in_memory_db) -> None:
    _, session_local = in_memory_db
    writer = StorageWriter()
    event = _mock_event()
    event_id = writer.write_event(event)
    hit = _mock_hit(event)
    hit_id = writer.write_rule_hit(hit, event_id)
    writer.write_alert_from_hit(hit, hit_id, event_id, event)
    with session_local() as session:
        assert session.query(EventRecord).count() == 1
        assert session.query(RuleHitRecord).count() == 1
        assert session.query(AlertRecord).count() == 1


def test_write_event_db_exception_returns_none(monkeypatch: pytest.MonkeyPatch, in_memory_db) -> None:
    writer = StorageWriter()

    @contextmanager
    def _broken_session():
        raise RuntimeError("forced failure")
        yield

    monkeypatch.setattr("storage.storage_writer.get_session", _broken_session)
    assert writer.write_event(_mock_event()) is None
