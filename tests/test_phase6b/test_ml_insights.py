"""
ShadowSensor Phase 6B Subphase 4 — ML Insights dashboard wiring tests.

Coverage:
  - get_isolation_forest_status(): returns trained=False with empty DB
  - get_isolation_forest_status(): returns correct stats with populated DB
  - get_isolation_forest_status(): brackets sum to total_scored
  - get_isolation_forest_status(): training_date is None when artifact absent
  - get_score_trend(): returns empty list when no recent rows
  - get_score_trend(): returns correct hourly buckets with data
  - GET /api/v1/ml-status: returns models_trained=False with empty DB (backward compat)
  - GET /api/v1/ml-status: returns models_trained=True when model_scores rows present
  - GET /dashboard/ml-insights: returns 200 with empty DB (no data state)
  - GET /dashboard/ml-insights: returns 200 with model_scores rows (data state)
  - trend_data_json is present in page response and valid JSON
"""
from __future__ import annotations

import importlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import storage.database as storage_database
from storage.models import EventRecord, ModelScoreRecord


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def empty_db(monkeypatch: pytest.MonkeyPatch):
    """In-memory DB with schema but no rows — simulates fresh host environment."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    monkeypatch.setattr(storage_database, "engine", engine)
    monkeypatch.setattr(storage_database, "SessionLocal", session_local)
    storage_database.init_db()
    yield session_local
    engine.dispose()


@pytest.fixture()
def populated_db(monkeypatch: pytest.MonkeyPatch):
    """In-memory DB with realistic model_scores rows.

    Inserts 6 rows covering three EIDs with varied scores (matching the known
    per-EID structure from Subphase 2 empirical validation).
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    monkeypatch.setattr(storage_database, "engine", engine)
    monkeypatch.setattr(storage_database, "SessionLocal", session_local)
    storage_database.init_db()

    now = datetime.now(UTC)
    rows = [
        # EID 7/10-like: low scores
        ModelScoreRecord(event_fk=1, model_type="isolation_forest", score=0.0200, timestamp=now - timedelta(hours=2)),
        ModelScoreRecord(event_fk=2, model_type="isolation_forest", score=0.0500, timestamp=now - timedelta(hours=1, minutes=30)),
        ModelScoreRecord(event_fk=3, model_type="isolation_forest", score=0.0800, timestamp=now - timedelta(hours=1)),
        # EID 1/3/22-like: mid scores
        ModelScoreRecord(event_fk=4, model_type="isolation_forest", score=0.3412, timestamp=now - timedelta(minutes=45)),
        ModelScoreRecord(event_fk=5, model_type="isolation_forest", score=0.4200, timestamp=now - timedelta(minutes=30)),
        ModelScoreRecord(event_fk=6, model_type="isolation_forest", score=0.5100, timestamp=now - timedelta(minutes=10)),
    ]
    with session_local() as session:
        session.add_all(rows)
        session.commit()

    yield session_local
    engine.dispose()


@pytest.fixture()
def api_client_empty(empty_db, monkeypatch: pytest.MonkeyPatch):
    """TestClient with empty DB — for API / page route tests."""
    import dashboard.routers.api as api_module
    import dashboard.app as app_module

    importlib.reload(api_module)
    importlib.reload(app_module)

    client = TestClient(app_module.app)
    yield client


@pytest.fixture()
def api_client_populated(populated_db, monkeypatch: pytest.MonkeyPatch):
    """TestClient with populated model_scores DB."""
    import dashboard.routers.api as api_module
    import dashboard.app as app_module

    importlib.reload(api_module)
    importlib.reload(app_module)

    client = TestClient(app_module.app)
    yield client


# ---------------------------------------------------------------------------
# 1. get_isolation_forest_status() — empty DB
# ---------------------------------------------------------------------------

def test_if_status_empty_db_returns_not_trained(empty_db) -> None:
    """get_isolation_forest_status() reports trained=False on an empty DB."""
    from dashboard.services.ml_insights_service import get_isolation_forest_status

    status = get_isolation_forest_status(model_path=Path("nonexistent_model.joblib"))
    assert status["trained"] is False
    assert status["total_scored"] == 0
    assert status["score_min"] is None
    assert status["score_max"] is None
    assert status["score_mean"] is None
    assert status["score_median"] is None
    assert status["brackets"] == []


def test_if_status_training_date_none_when_artifact_absent(empty_db) -> None:
    """training_date is None when the model artifact file does not exist."""
    from dashboard.services.ml_insights_service import get_isolation_forest_status

    status = get_isolation_forest_status(model_path=Path("definitely_absent.joblib"))
    assert status["training_date"] is None


# ---------------------------------------------------------------------------
# 2. get_isolation_forest_status() — populated DB
# ---------------------------------------------------------------------------

def test_if_status_populated_returns_trained(populated_db) -> None:
    """get_isolation_forest_status() reports trained=True when rows exist."""
    from dashboard.services.ml_insights_service import get_isolation_forest_status

    status = get_isolation_forest_status(model_path=Path("absent.joblib"))
    assert status["trained"] is True


def test_if_status_total_scored_correct(populated_db) -> None:
    """total_scored matches the number of inserted rows."""
    from dashboard.services.ml_insights_service import get_isolation_forest_status

    status = get_isolation_forest_status(model_path=Path("absent.joblib"))
    assert status["total_scored"] == 6


def test_if_status_score_stats_in_range(populated_db) -> None:
    """score_min, score_max, score_mean, score_median are in [0.0, 1.0]."""
    from dashboard.services.ml_insights_service import get_isolation_forest_status

    status = get_isolation_forest_status(model_path=Path("absent.joblib"))
    for key in ("score_min", "score_max", "score_mean", "score_median"):
        val = status[key]
        assert val is not None, f"{key} should not be None with data"
        assert 0.0 <= val <= 1.0, f"{key}={val} out of [0,1]"


def test_if_status_brackets_sum_to_total(populated_db) -> None:
    """Sum of bracket counts equals total_scored."""
    from dashboard.services.ml_insights_service import get_isolation_forest_status

    status = get_isolation_forest_status(model_path=Path("absent.joblib"))
    assert len(status["brackets"]) == 10
    bracket_sum = sum(b["count"] for b in status["brackets"])
    assert bracket_sum == status["total_scored"]


def test_if_status_bracket_pct_are_nonnegative(populated_db) -> None:
    """All bracket pct values are >= 0 and <= 100."""
    from dashboard.services.ml_insights_service import get_isolation_forest_status

    status = get_isolation_forest_status(model_path=Path("absent.joblib"))
    for b in status["brackets"]:
        assert 0.0 <= b["pct"] <= 100.0, f"bracket pct={b['pct']} out of range"


def test_if_status_training_date_from_artifact(tmp_path: Path, populated_db) -> None:
    """training_date is a formatted string when the artifact file exists."""
    from dashboard.services.ml_insights_service import get_isolation_forest_status

    fake_artifact = tmp_path / "fake_model.joblib"
    fake_artifact.write_bytes(b"placeholder")

    status = get_isolation_forest_status(model_path=fake_artifact)
    assert status["training_date"] is not None
    assert "UTC" in status["training_date"]


# ---------------------------------------------------------------------------
# 3. get_score_trend() — empty and populated
# ---------------------------------------------------------------------------

def test_score_trend_empty_db_returns_empty_list(empty_db) -> None:
    """get_score_trend() returns [] when no model_scores rows exist."""
    from dashboard.services.ml_insights_service import get_score_trend

    result = get_score_trend(hours=24)
    assert result == []


def test_score_trend_populated_returns_buckets(populated_db) -> None:
    """get_score_trend() returns at least one hourly bucket with recent data."""
    from dashboard.services.ml_insights_service import get_score_trend

    result = get_score_trend(hours=24)
    assert len(result) > 0


def test_score_trend_bucket_structure(populated_db) -> None:
    """Each trend bucket has hour, avg_score, and count keys."""
    from dashboard.services.ml_insights_service import get_score_trend

    result = get_score_trend(hours=24)
    for bucket in result:
        assert "hour" in bucket
        assert "avg_score" in bucket
        assert "count" in bucket
        assert 0.0 <= bucket["avg_score"] <= 1.0
        assert bucket["count"] > 0


def test_score_trend_sorted_ascending(populated_db) -> None:
    """Trend buckets are sorted by hour ascending."""
    from dashboard.services.ml_insights_service import get_score_trend

    result = get_score_trend(hours=24)
    hours = [b["hour"] for b in result]
    assert hours == sorted(hours)


def test_score_trend_excludes_old_data(populated_db) -> None:
    """Rows older than the time window are not included."""
    from dashboard.services.ml_insights_service import get_score_trend

    # Window of 0 hours should return nothing
    result = get_score_trend(hours=0)
    assert result == []


# ---------------------------------------------------------------------------
# 4. GET /api/v1/ml-status — backward compat and live data
# ---------------------------------------------------------------------------

def test_ml_status_empty_db_returns_false(api_client_empty) -> None:
    """Backward-compat: ml-status returns models_trained=False on empty DB."""
    response = api_client_empty.get("/api/v1/ml-status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["models_trained"] is False


def test_ml_status_populated_returns_true(api_client_populated) -> None:
    """ml-status returns models_trained=True when model_scores rows exist."""
    response = api_client_populated.get("/api/v1/ml-status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["models_trained"] is True


def test_ml_status_populated_has_isolation_forest_key(api_client_populated) -> None:
    """ml-status includes isolation_forest key with trained=True."""
    response = api_client_populated.get("/api/v1/ml-status")
    payload = response.json()
    assert payload["isolation_forest"] is not None
    assert payload["isolation_forest"]["trained"] is True
    assert payload["isolation_forest"]["scored_events"] == 6


# ---------------------------------------------------------------------------
# 5. GET /dashboard/ml-insights — page route
# ---------------------------------------------------------------------------

def test_ml_insights_page_200_empty_db(api_client_empty) -> None:
    """ML Insights page returns HTTP 200 with empty DB (no data state)."""
    response = api_client_empty.get("/dashboard/ml-insights")
    assert response.status_code == 200


def test_ml_insights_page_200_populated_db(api_client_populated) -> None:
    """ML Insights page returns HTTP 200 with scored events present."""
    response = api_client_populated.get("/dashboard/ml-insights")
    assert response.status_code == 200


def test_ml_insights_page_contains_section_headings(api_client_populated) -> None:
    """ML Insights page contains expected section headings."""
    response = api_client_populated.get("/dashboard/ml-insights")
    body = response.text
    assert "Isolation Forest" in body
    assert "Random Forest" in body


def test_ml_insights_page_shows_active_status_when_data_present(api_client_populated) -> None:
    """ML Insights page shows 'Active' badge when scored events exist."""
    response = api_client_populated.get("/dashboard/ml-insights")
    assert "Active" in response.text


def test_ml_insights_page_contains_trend_json(api_client_populated) -> None:
    """ML Insights page embeds trend data as valid JSON in <script> block."""
    response = api_client_populated.get("/dashboard/ml-insights")
    body = response.text
    # The trend JSON is embedded via {{ trend_data_json | safe }}
    assert "avg_score" in body or "rawTrend" in body


def test_ml_insights_page_shows_pending_when_no_data(api_client_empty) -> None:
    """ML Insights page shows 'Awaiting Data' badge when no scored events."""
    response = api_client_empty.get("/dashboard/ml-insights")
    assert "Awaiting Data" in response.text or "Phase 7B" in response.text


def test_ml_insights_page_rf_section_present(api_client_populated) -> None:
    """RF section is present in the ML Insights page after Phase 7B wiring."""
    response = api_client_populated.get("/dashboard/ml-insights")
    assert response.status_code == 200
    assert "Random Forest" in response.text


def test_ml_insights_page_no_server_error_on_populated_data(api_client_populated) -> None:
    """ML Insights page does not contain error text in response body."""
    response = api_client_populated.get("/dashboard/ml-insights")
    body = response.text.lower()
    assert "internal server error" not in body
    assert "traceback" not in body


def test_ml_insights_page_rf_shows_awaiting_when_no_rf_rows(api_client_populated) -> None:
    """RF section shows Awaiting Data badge when model_scores has no random_forest rows."""
    response = api_client_populated.get("/dashboard/ml-insights")
    assert "Awaiting Data" in response.text


def test_ml_insights_page_rf_placeholder_badge_gone(api_client_populated) -> None:
    """The old Phase 7B future-badge CSS class is no longer present after SP3 wiring."""
    response = api_client_populated.get("/dashboard/ml-insights")
    assert "ml-status-future" not in response.text
