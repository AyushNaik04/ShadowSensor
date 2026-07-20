"""Unit tests for the Phase 3 AlertManager stub."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from alerting.alert_manager import AlertManager
from normalizer.models import ProcessCreateEvent
from rules.schema import RuleHit
from storage import database as storage_database
from storage.models import AlertRecord
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
    yield test_session_local
    test_engine.dispose()


def _mock_event() -> ProcessCreateEvent:
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


def test_process_hit_calls_write_alert_once() -> None:
    writer = Mock(spec=StorageWriter)
    manager = AlertManager(writer)
    manager.process_hit("hit", 10, 11, {"raw": "event"})
    writer.write_alert_from_hit.assert_called_once_with("hit", 10, 11, {"raw": "event"})


def test_process_hit_does_not_raise_when_writer_raises() -> None:
    writer = Mock(spec=StorageWriter)
    writer.write_alert_from_hit.side_effect = RuntimeError("simulated writer failure")
    manager = AlertManager(writer)
    manager.process_hit("hit", 10, 11, {"raw": "event"})


def test_process_hit_persists_alert_row_with_rule_id(in_memory_db) -> None:
    session_local = in_memory_db
    writer = StorageWriter()
    manager = AlertManager(writer)
    event = _mock_event()
    event_id = writer.write_event(event)
    hit = _mock_hit(event)
    hit_id = writer.write_rule_hit(hit, event_id)

    manager.process_hit(hit, hit_id, event_id, event)

    with session_local() as session:
        alert = session.query(AlertRecord).first()
        assert alert is not None
        assert alert.rule_id == "PS_TEST_001"
