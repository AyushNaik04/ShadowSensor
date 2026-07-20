"""Unit tests for KQL parse-tree to SQLAlchemy transformation."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from dashboard.kql.parser import KQLParser
from dashboard.kql.transformer import KQLTransformError, KQLTransformer
from storage import database as storage_database
from storage.models import AlertRecord


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


@pytest.fixture()
def seeded_alerts(in_memory_db):
    session_local = in_memory_db
    base_time = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    with session_local() as session:
        session.add_all(
            [
                AlertRecord(
                    rule_hit_fk=None,
                    event_fk=None,
                    rule_id="R1",
                    rule_name="powershell suspicious",
                    severity="High",
                    mitre_technique="T1059.001",
                    mitre_tactic="Execution",
                    process_image="lsass.exe",
                    process_pid=400,
                    command_line="powershell -enc AAA",
                    parent_image=r"C:\Windows\explorer.exe",
                    status="open",
                    suspected_families=None,
                    timestamp=base_time,
                ),
                AlertRecord(
                    rule_hit_fk=None,
                    event_fk=None,
                    rule_id="R2",
                    rule_name="low signal",
                    severity="Low",
                    mitre_technique="T1001",
                    mitre_tactic="Defense Evasion",
                    process_image=r"C:\Windows\System32\notepad.exe",
                    process_pid=500,
                    command_line="notepad.exe",
                    parent_image=r"C:\Windows\explorer.exe",
                    status="resolved",
                    suspected_families=None,
                    timestamp=base_time,
                ),
            ]
        )
        session.commit()
    return session_local


def _query_ids(session_local, where_clause):
    with session_local() as session:
        return [row.id for row in session.query(AlertRecord).filter(where_clause).all()]


def test_severity_high_matches_high_row_only(seeded_alerts) -> None:
    parser = KQLParser()
    where_clause = KQLTransformer("alerts").transform(parser.parse("severity:High"))
    ids = _query_ids(seeded_alerts, where_clause)
    assert len(ids) == 1


def test_compound_and_filter_works(seeded_alerts) -> None:
    parser = KQLParser()
    where_clause = KQLTransformer("alerts").transform(parser.parse("severity:High AND status:open"))
    ids = _query_ids(seeded_alerts, where_clause)
    assert len(ids) == 1


def test_rule_name_wildcard_matches_powershell(seeded_alerts) -> None:
    parser = KQLParser()
    where_clause = KQLTransformer("alerts").transform(parser.parse("rule_name:power*"))
    ids = _query_ids(seeded_alerts, where_clause)
    assert len(ids) == 1


def test_timestamp_between_includes_boundaries(seeded_alerts) -> None:
    parser = KQLParser()
    where_clause = KQLTransformer("alerts").transform(
        parser.parse("timestamp:[2026-06-15 TO 2026-06-16]")
    )
    ids = _query_ids(seeded_alerts, where_clause)
    assert len(ids) == 2


def test_not_low_excludes_low_rows(seeded_alerts) -> None:
    parser = KQLParser()
    where_clause = KQLTransformer("alerts").transform(parser.parse("NOT severity:Low"))
    ids = _query_ids(seeded_alerts, where_clause)
    assert len(ids) == 1


def test_process_image_wildcard_matches_lsass(seeded_alerts) -> None:
    parser = KQLParser()
    where_clause = KQLTransformer("alerts").transform(parser.parse("process_image:lsass*"))
    ids = _query_ids(seeded_alerts, where_clause)
    assert len(ids) == 1


def test_unknown_field_raises_transform_error() -> None:
    parser = KQLParser()
    tree = parser.parse("nonexistent:value")
    with pytest.raises(KQLTransformError):
        KQLTransformer("alerts").transform(tree)


def test_nested_query_produces_filter_expression() -> None:
    parser = KQLParser()
    tree = parser.parse("severity:High AND (status:open OR NOT status:resolved)")
    expression = KQLTransformer("alerts").transform(tree)
    assert expression is not None


def test_transform_none_returns_none() -> None:
    assert KQLTransformer("alerts").transform(None) is None
