"""
ShadowSensor Phase 7B Subphase 3 — Random Forest ML Insights tests.

Coverage:
  - get_random_forest_status(): returns trained=False with empty DB
  - get_random_forest_status(): returns trained=True when RF rows exist
  - get_random_forest_status(): total_scored equals inserted RF row count
  - get_random_forest_status(): training_date is None when artifact absent
  - get_random_forest_status(): brackets sum to total_scored when data present
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import storage.database as storage_database
from storage.models import ModelScoreRecord


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
    """In-memory DB with random_forest model_scores rows."""
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
        ModelScoreRecord(event_fk=1, model_type="random_forest", score=0.1200, timestamp=now - timedelta(hours=2)),
        ModelScoreRecord(event_fk=2, model_type="random_forest", score=0.2500, timestamp=now - timedelta(hours=1, minutes=30)),
        ModelScoreRecord(event_fk=3, model_type="random_forest", score=0.3800, timestamp=now - timedelta(hours=1)),
        ModelScoreRecord(event_fk=4, model_type="random_forest", score=0.6100, timestamp=now - timedelta(minutes=45)),
        ModelScoreRecord(event_fk=5, model_type="random_forest", score=0.7400, timestamp=now - timedelta(minutes=30)),
        ModelScoreRecord(event_fk=6, model_type="random_forest", score=0.8900, timestamp=now - timedelta(minutes=10)),
    ]
    with session_local() as session:
        session.add_all(rows)
        session.commit()

    yield session_local
    engine.dispose()


def test_rf_status_empty_db_returns_not_trained(empty_db) -> None:
    """get_random_forest_status() reports trained=False on an empty DB."""
    from dashboard.services.ml_insights_service import get_random_forest_status

    status = get_random_forest_status(model_path=Path("nonexistent_model.joblib"))
    assert status["trained"] is False
    assert status["total_scored"] == 0
    assert status["score_min"] is None
    assert status["score_max"] is None
    assert status["score_mean"] is None
    assert status["score_median"] is None
    assert status["brackets"] == []


def test_rf_status_populated_returns_trained(populated_db) -> None:
    """get_random_forest_status() reports trained=True when RF rows exist."""
    from dashboard.services.ml_insights_service import get_random_forest_status

    status = get_random_forest_status(model_path=Path("absent.joblib"))
    assert status["trained"] is True


def test_rf_status_total_scored_equals_inserted_rows(populated_db) -> None:
    """total_scored matches the number of inserted RF rows."""
    from dashboard.services.ml_insights_service import get_random_forest_status

    status = get_random_forest_status(model_path=Path("absent.joblib"))
    assert status["total_scored"] == 6


def test_rf_status_training_date_none_when_artifact_absent(empty_db) -> None:
    """training_date is None when the model artifact file does not exist."""
    from dashboard.services.ml_insights_service import get_random_forest_status

    status = get_random_forest_status(model_path=Path("definitely_absent.joblib"))
    assert status["training_date"] is None


def test_rf_status_brackets_sum_to_total(populated_db) -> None:
    """Sum of bracket counts equals total_scored when RF data is present."""
    from dashboard.services.ml_insights_service import get_random_forest_status

    status = get_random_forest_status(model_path=Path("absent.joblib"))
    assert len(status["brackets"]) == 10
    bracket_sum = sum(b["count"] for b in status["brackets"])
    assert bracket_sum == status["total_scored"]
