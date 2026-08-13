"""
ShadowSensor Phase 6B — Subphase 3 scoring integration tests.

Coverage:
  - _event_to_extractor_row(): correct mapping for each known event type
  - _event_to_extractor_row(): raises TypeError for non-dataclass input
  - _coerce_event_timestamp(): handles datetime, ISO string, None
  - EventScorer.__init__(): loads from valid artifact; raises FileNotFoundError
    when model artifact is absent
  - EventScorer.score_and_persist(): returns float in [0.0, 1.0] for valid events
    of each known EID
  - EventScorer.score_and_persist(): returns score even when event_db_id is None
    (no DB write attempted)
  - EventScorer.score_and_persist(): returns None for non-dataclass event (graceful)
  - handle_persist_and_score_event(): True on full success (persist + score)
  - handle_persist_and_score_event(): False when persistence raises
  - handle_persist_and_score_event(): True when scoring raises (persistence succeeded)
  - handle_persist_and_score_event(): True when scorer is None (scoring disabled,
    persistence still runs)
  - Model loaded once at scorer construction, NOT per-event (artifact object
    identity is stable across multiple score_and_persist calls)
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest

from ml.features.feature_spec import FEATURE_NAMES
from ml.training.train_isolation_forest import load_artifact, train_and_persist
from ml.scoring.scorer import (
    EventScorer,
    _coerce_event_timestamp,
    _event_to_extractor_row,
)
from normalizer.models import (
    CreateRemoteThreadEvent,
    DnsQueryEvent,
    ImageLoadEvent,
    NetworkConnectEvent,
    OpenProcessEvent,
    ProcessCreateEvent,
)
from scripts.run_pipeline import handle_persist_and_score_event


# ---------------------------------------------------------------------------
# Helpers — synthetic events and artifacts
# ---------------------------------------------------------------------------

def _make_process_create(ts: str = "2026-07-28T10:00:00") -> ProcessCreateEvent:
    return ProcessCreateEvent(
        event_id=1,
        utc_time=ts,
        computer="TESTHOST",
        process_guid="{00000000-0000-0000-0000-000000000001}",
        process_id=1234,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        current_directory=r"C:\Users\test",
        user="TESTHOST\\test",
        parent_process_id=5678,
        parent_image=r"C:\Windows\explorer.exe",
        parent_command_line=None,
        integrity_level="Medium",
        hashes=None,
    )


def _make_network_connect() -> NetworkConnectEvent:
    return NetworkConnectEvent(
        event_id=3,
        utc_time="2026-07-28T10:01:00",
        computer="TESTHOST",
        process_guid="{00000000-0000-0000-0000-000000000002}",
        process_id=1234,
        image=r"C:\Windows\System32\svchost.exe",
        user=None,
        protocol="tcp",
        initiated=True,
        source_ip="192.168.1.100",
        source_port=55000,
        destination_ip="8.8.8.8",
        destination_hostname="dns.google",
        destination_port=443,
    )


def _make_image_load() -> ImageLoadEvent:
    return ImageLoadEvent(
        event_id=7,
        utc_time="2026-07-28T10:02:00",
        computer="TESTHOST",
        process_guid="{00000000-0000-0000-0000-000000000003}",
        process_id=1234,
        image=r"C:\Windows\System32\notepad.exe",
        image_loaded=r"C:\Windows\System32\kernel32.dll",
        signed=True,
        signature="Microsoft Windows",
        signature_status="Valid",
        hashes=None,
    )


def _make_open_process() -> OpenProcessEvent:
    return OpenProcessEvent(
        event_id=10,
        utc_time="2026-07-28T10:03:00",
        computer="TESTHOST",
        source_process_id=1234,
        source_image=r"C:\Windows\System32\notepad.exe",
        target_process_id=5678,
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x0010",
        call_trace=None,
    )


def _make_dns_query() -> DnsQueryEvent:
    return DnsQueryEvent(
        event_id=22,
        utc_time="2026-07-28T10:04:00",
        computer="TESTHOST",
        process_id=1234,
        image=r"C:\Windows\System32\chrome.exe",
        query_name="example.com",
        query_status="0",
        query_results="1.2.3.4",
    )


def _make_create_remote_thread() -> CreateRemoteThreadEvent:
    return CreateRemoteThreadEvent(
        event_id=8,
        utc_time="2026-07-28T10:05:00",
        computer="TESTHOST",
        source_process_id=1234,
        source_image=r"C:\Windows\System32\notepad.exe",
        target_process_id=5678,
        target_image=r"C:\Windows\System32\svchost.exe",
        new_thread_id=999,
        start_address="0x7FFE0000",
        start_module=None,
        start_function=None,
    )


@pytest.fixture()
def synthetic_df() -> pd.DataFrame:
    """50-row synthetic feature DataFrame with all required columns."""
    rng = np.random.RandomState(0)
    return pd.DataFrame(
        {name: rng.randint(0, 5, size=50).astype(float) for name in FEATURE_NAMES}
    )


@pytest.fixture()
def trained_artifact_path(synthetic_df: pd.DataFrame, tmp_path: Path) -> Path:
    """Train on synthetic data; return path to the persisted artifact."""
    csv_path = tmp_path / "synthetic.csv"
    synthetic_df.assign(label=0).to_csv(csv_path, index=False)
    model_path = tmp_path / "test_model.joblib"
    train_and_persist(csv_path=csv_path, model_path=model_path)
    return model_path


@pytest.fixture()
def scorer(trained_artifact_path: Path) -> EventScorer:
    """EventScorer backed by the synthetic trained artifact."""
    return EventScorer(model_path=trained_artifact_path)


# ---------------------------------------------------------------------------
# 1. _event_to_extractor_row — mapping correctness per EID
# ---------------------------------------------------------------------------

def test_event_to_row_eid1_fields() -> None:
    """ProcessCreateEvent maps to correct event_type_id and image."""
    ev = _make_process_create()
    row = _event_to_extractor_row(ev)
    assert row["event_type_id"] == 1
    assert row["image"] == r"C:\Windows\System32\cmd.exe"
    assert row["timestamp"] == ev.utc_time
    assert isinstance(row["raw_json"], str)


def test_event_to_row_eid3_image() -> None:
    """NetworkConnectEvent maps to event_type_id=3; image from 'image' attr."""
    ev = _make_network_connect()
    row = _event_to_extractor_row(ev)
    assert row["event_type_id"] == 3
    assert row["image"] == r"C:\Windows\System32\svchost.exe"


def test_event_to_row_eid7_image() -> None:
    """ImageLoadEvent maps to event_type_id=7."""
    ev = _make_image_load()
    row = _event_to_extractor_row(ev)
    assert row["event_type_id"] == 7


def test_event_to_row_eid8_source_image() -> None:
    """CreateRemoteThreadEvent maps to event_type_id=8; image from 'source_image'."""
    ev = _make_create_remote_thread()
    row = _event_to_extractor_row(ev)
    assert row["event_type_id"] == 8
    assert row["image"] == r"C:\Windows\System32\notepad.exe"


def test_event_to_row_eid10_source_image() -> None:
    """OpenProcessEvent maps to event_type_id=10; image from 'source_image'."""
    ev = _make_open_process()
    row = _event_to_extractor_row(ev)
    assert row["event_type_id"] == 10
    assert row["image"] == r"C:\Windows\System32\notepad.exe"


def test_event_to_row_eid22_image() -> None:
    """DnsQueryEvent maps to event_type_id=22."""
    ev = _make_dns_query()
    row = _event_to_extractor_row(ev)
    assert row["event_type_id"] == 22


def test_event_to_row_raw_json_is_string() -> None:
    """raw_json field is a JSON-serializable string."""
    import json
    ev = _make_process_create()
    row = _event_to_extractor_row(ev)
    parsed = json.loads(row["raw_json"])
    assert isinstance(parsed, dict)
    assert "command_line" in parsed


def test_event_to_row_raises_for_non_dataclass() -> None:
    """TypeError is raised when a non-dataclass is passed."""
    with pytest.raises(TypeError, match="Expected a dataclass event"):
        _event_to_extractor_row({"event_type_id": 1})


# ---------------------------------------------------------------------------
# 2. _coerce_event_timestamp
# ---------------------------------------------------------------------------

def test_coerce_timestamp_datetime_passthrough() -> None:
    """A datetime object is returned as-is."""
    now = datetime(2026, 7, 28, 10, 0, 0, tzinfo=timezone.utc)
    ev = _make_process_create()
    object.__setattr__(ev, "utc_time", now)  # type: ignore[call-arg]
    # Direct call:
    result = _coerce_event_timestamp(ev)
    assert result == now


def test_coerce_timestamp_iso_string() -> None:
    """ISO string is parsed to a datetime."""
    ev = _make_process_create("2026-07-28T10:00:00")
    result = _coerce_event_timestamp(ev)
    assert isinstance(result, datetime)
    assert result.hour == 10


def test_coerce_timestamp_none_falls_back_to_utcnow() -> None:
    """When utc_time is None or missing, UTC now is returned."""

    @dataclasses.dataclass
    class NoTsEvent:
        event_id: int = 1

    result = _coerce_event_timestamp(NoTsEvent())
    assert isinstance(result, datetime)


# ---------------------------------------------------------------------------
# 3. EventScorer construction
# ---------------------------------------------------------------------------

def test_scorer_loads_from_valid_artifact(trained_artifact_path: Path) -> None:
    """EventScorer constructs without error from a valid model artifact."""
    sc = EventScorer(model_path=trained_artifact_path)
    assert sc._artifact is not None
    assert "model" in sc._artifact
    assert "train_score_min" in sc._artifact
    assert "train_score_max" in sc._artifact


def test_scorer_raises_when_model_missing(tmp_path: Path) -> None:
    """EventScorer raises FileNotFoundError when the artifact file doesn't exist."""
    with pytest.raises(FileNotFoundError):
        EventScorer(model_path=tmp_path / "nonexistent.joblib")


def test_scorer_artifact_identity_stable_across_calls(scorer: EventScorer) -> None:
    """Artifact object is the same instance on repeated calls — no re-loading."""
    artifact_id_first = id(scorer._artifact)
    ev = _make_process_create()
    scorer.score_and_persist(ev, event_db_id=None)
    scorer.score_and_persist(ev, event_db_id=None)
    assert id(scorer._artifact) == artifact_id_first, (
        "Artifact was reloaded between calls — model must be loaded once only."
    )


# ---------------------------------------------------------------------------
# 4. EventScorer.score_and_persist — score range
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("event_fn", [
    _make_process_create,
    _make_network_connect,
    _make_image_load,
    _make_open_process,
    _make_dns_query,
    _make_create_remote_thread,
])
def test_score_in_unit_interval_all_eids(event_fn, scorer: EventScorer) -> None:
    """score_and_persist() returns a float in [0.0, 1.0] for every known EID."""
    ev = event_fn()
    score = scorer.score_and_persist(ev, event_db_id=None)
    assert score is not None, f"score_and_persist returned None for {type(ev).__name__}"
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0, f"Score {score} out of range for {type(ev).__name__}"


def test_score_returns_score_when_event_db_id_none(scorer: EventScorer) -> None:
    """score_and_persist() computes and returns a score when event_db_id is None."""
    ev = _make_process_create()
    score = scorer.score_and_persist(ev, event_db_id=None)
    assert score is not None
    assert 0.0 <= score <= 1.0


def test_score_returns_none_for_non_dataclass(scorer: EventScorer) -> None:
    """score_and_persist() returns None gracefully when event is not a dataclass."""
    score = scorer.score_and_persist({"event_type_id": 1}, event_db_id=None)
    assert score is None


def test_score_and_persist_writes_model_scores_row(
    scorer: EventScorer, tmp_path: Path
) -> None:
    """score_and_persist() writes a ModelScoreRecord row when event_db_id is given.

    Verifies via direct SQLite query (not ORM object after session close) to
    avoid DetachedInstanceError.
    """
    import sqlite3

    db_path = tmp_path / "test_scoring.db"

    from sqlalchemy import create_engine

    import storage.database as db_mod
    import storage.models as models_mod

    # Build an isolated test engine and create all tables.
    test_engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    db_mod.Base.metadata.create_all(bind=test_engine)

    from contextlib import contextmanager
    from sqlalchemy.orm import sessionmaker

    TestSession = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)

    @contextmanager
    def _test_get_session():
        session = TestSession()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    with patch("ml.scoring.scorer.get_session", _test_get_session):
        ev = _make_process_create()
        score = scorer.score_and_persist(ev, event_db_id=42)

    assert score is not None
    assert 0.0 <= score <= 1.0

    # Verify directly via raw SQLite — no ORM session dependency.
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT event_fk, model_type, score FROM model_scores").fetchall()
    conn.close()

    # SP2 onwards: scorer may write both isolation_forest and random_forest rows.
    # Assert at least one row exists, then verify the isolation_forest row specifically.
    assert len(rows) >= 1, f"Expected at least 1 model_scores row; got {len(rows)}"
    if_rows = [r for r in rows if r["model_type"] == "isolation_forest"]
    assert len(if_rows) == 1, f"Expected exactly 1 isolation_forest row; got {len(if_rows)}"
    row = if_rows[0]
    assert row["event_fk"] == 42
    assert row["model_type"] == "isolation_forest"
    assert 0.0 <= row["score"] <= 1.0


# ---------------------------------------------------------------------------
# 5. handle_persist_and_score_event — pipeline integration
# ---------------------------------------------------------------------------

def _make_mock_storage_writer(event_db_id: int | None = 101) -> MagicMock:
    """Return a mock StorageWriter whose write_event() returns event_db_id."""
    sw = MagicMock()
    sw.write_event.return_value = event_db_id
    sw.write_rule_hit.return_value = 1
    return sw


def _make_mock_alert_manager() -> MagicMock:
    am = MagicMock()
    am.process_hit.return_value = None
    return am


def test_handle_persist_and_score_returns_true_on_success(
    scorer: EventScorer,
) -> None:
    """handle_persist_and_score_event returns True when both persist and score succeed."""
    sw = _make_mock_storage_writer(event_db_id=55)
    am = _make_mock_alert_manager()
    ev = _make_process_create()

    with patch.object(scorer, "score_and_persist", return_value=0.3) as mock_score:
        result = handle_persist_and_score_event(ev, [], sw, am, scorer)

    assert result is True
    sw.write_event.assert_called_once()
    mock_score.assert_called_once_with(ev, 55)


def test_handle_persist_and_score_returns_false_on_persist_failure(
    scorer: EventScorer,
) -> None:
    """handle_persist_and_score_event returns False when persistence raises."""
    sw = _make_mock_storage_writer()
    sw.write_event.side_effect = RuntimeError("DB gone")
    am = _make_mock_alert_manager()
    ev = _make_process_create()

    with patch.object(scorer, "score_and_persist") as mock_score:
        result = handle_persist_and_score_event(ev, [], sw, am, scorer)

    assert result is False
    mock_score.assert_not_called()


def test_handle_persist_and_score_returns_true_when_scoring_raises(
    scorer: EventScorer,
) -> None:
    """handle_persist_and_score_event returns True even when scoring raises.

    Persistence success is the primary success condition; scoring failure
    must not prevent True being returned or crash the caller.
    """
    sw = _make_mock_storage_writer(event_db_id=77)
    am = _make_mock_alert_manager()
    ev = _make_process_create()

    with patch.object(scorer, "score_and_persist", side_effect=RuntimeError("scorer bug")):
        result = handle_persist_and_score_event(ev, [], sw, am, scorer)

    assert result is True


def test_handle_persist_and_score_with_none_scorer_still_persists() -> None:
    """When scorer is None (model not loaded), persistence still runs and returns True."""
    sw = _make_mock_storage_writer(event_db_id=88)
    am = _make_mock_alert_manager()
    ev = _make_process_create()

    result = handle_persist_and_score_event(ev, [], sw, am, scorer=None)

    assert result is True
    sw.write_event.assert_called_once()


def test_handle_persist_and_score_with_none_event_db_id_skips_scoring(
    scorer: EventScorer,
) -> None:
    """When write_event returns None, scoring is skipped (no valid FK)."""
    sw = _make_mock_storage_writer(event_db_id=None)
    am = _make_mock_alert_manager()
    ev = _make_process_create()

    with patch.object(scorer, "score_and_persist") as mock_score:
        result = handle_persist_and_score_event(ev, [], sw, am, scorer)

    assert result is True
    mock_score.assert_not_called()
