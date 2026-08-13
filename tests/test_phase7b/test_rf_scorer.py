"""
ShadowSensor Phase 7B — Subphase 2 RF scorer integration tests.

Coverage:
  - EventScorer._rf_artifact is None when RF_MODEL_PATH does not exist
  - EventScorer._rf_artifact is loaded when RF_MODEL_PATH points to a valid artifact
  - score_and_persist() writes IF + RF rows when both artifacts are loaded
  - RF row has model_type == "random_forest" and score in [0.0, 1.0]
  - RF scoring failure is non-fatal (IF score still returned; only IF row written)
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ml.features.feature_spec import FEATURE_NAMES
from ml.scoring.scorer import EventScorer
from ml.training.train_isolation_forest import train_and_persist
from normalizer.models import ProcessCreateEvent


def _make_rf_artifact(tmp_path):
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from ml.training.train_random_forest import RF_FEATURE_NAMES
    X = np.random.RandomState(0).rand(20, len(RF_FEATURE_NAMES))
    y = np.array([0] * 10 + [1] * 10)
    clf = RandomForestClassifier(n_estimators=5, random_state=0)
    clf.fit(X, y)
    artifact = {"model": clf, "feature_names": RF_FEATURE_NAMES, "cv_metrics": {}}
    path = tmp_path / "random_forest.joblib"
    joblib.dump(artifact, path)
    return path


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


@pytest.fixture()
def synthetic_df() -> pd.DataFrame:
    """50-row synthetic feature DataFrame with all required columns."""
    rng = np.random.RandomState(0)
    return pd.DataFrame(
        {name: rng.randint(0, 5, size=50).astype(float) for name in FEATURE_NAMES}
    )


@pytest.fixture()
def trained_artifact_path(synthetic_df: pd.DataFrame, tmp_path: Path) -> Path:
    """Train Isolation Forest on synthetic data; return path to the artifact."""
    csv_path = tmp_path / "synthetic.csv"
    synthetic_df.assign(label=0).to_csv(csv_path, index=False)
    model_path = tmp_path / "test_model.joblib"
    train_and_persist(csv_path=csv_path, model_path=model_path)
    return model_path


def _make_test_session(tmp_path: Path):
    """Return (db_path, get_session context manager) backed by a tmp SQLite DB."""
    import storage.database as db_mod

    db_path = tmp_path / "test_rf_scoring.db"
    test_engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    db_mod.Base.metadata.create_all(bind=test_engine)
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

    return db_path, _test_get_session


def _read_model_scores(db_path: Path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT event_fk, model_type, score FROM model_scores"
    ).fetchall()
    conn.close()
    return list(rows)


def test_rf_artifact_none_when_model_missing(
    trained_artifact_path: Path, tmp_path: Path, monkeypatch
) -> None:
    """EventScorer._rf_artifact is None when RF_MODEL_PATH does not exist."""
    monkeypatch.setattr(
        "ml.scoring.scorer.RF_MODEL_PATH",
        tmp_path / "nonexistent.joblib",
    )
    scorer = EventScorer(model_path=trained_artifact_path)
    assert scorer._rf_artifact is None


def test_rf_artifact_loaded_when_model_exists(
    trained_artifact_path: Path, tmp_path: Path, monkeypatch
) -> None:
    """EventScorer._rf_artifact is not None when RF_MODEL_PATH is a valid artifact."""
    rf_path = _make_rf_artifact(tmp_path)
    monkeypatch.setattr("ml.scoring.scorer.RF_MODEL_PATH", rf_path)
    scorer = EventScorer(model_path=trained_artifact_path)
    assert scorer._rf_artifact is not None


def test_score_and_persist_writes_if_and_rf_rows(
    trained_artifact_path: Path, tmp_path: Path, monkeypatch
) -> None:
    """score_and_persist() writes exactly 2 rows when both artifacts are loaded."""
    rf_path = _make_rf_artifact(tmp_path)
    monkeypatch.setattr("ml.scoring.scorer.RF_MODEL_PATH", rf_path)
    scorer = EventScorer(model_path=trained_artifact_path)
    db_path, test_get_session = _make_test_session(tmp_path)

    with patch("ml.scoring.scorer.get_session", test_get_session):
        score = scorer.score_and_persist(_make_process_create(), event_db_id=42)

    assert score is not None
    rows = _read_model_scores(db_path)
    assert len(rows) == 2, f"Expected 2 model_scores rows; got {len(rows)}"


def test_rf_row_model_type_is_random_forest(
    trained_artifact_path: Path, tmp_path: Path, monkeypatch
) -> None:
    """The RF row has model_type == 'random_forest'."""
    rf_path = _make_rf_artifact(tmp_path)
    monkeypatch.setattr("ml.scoring.scorer.RF_MODEL_PATH", rf_path)
    scorer = EventScorer(model_path=trained_artifact_path)
    db_path, test_get_session = _make_test_session(tmp_path)

    with patch("ml.scoring.scorer.get_session", test_get_session):
        scorer.score_and_persist(_make_process_create(), event_db_id=42)

    rows = _read_model_scores(db_path)
    rf_rows = [r for r in rows if r["model_type"] == "random_forest"]
    assert len(rf_rows) == 1


def test_rf_row_score_in_unit_interval(
    trained_artifact_path: Path, tmp_path: Path, monkeypatch
) -> None:
    """The RF row score is a float in [0.0, 1.0]."""
    rf_path = _make_rf_artifact(tmp_path)
    monkeypatch.setattr("ml.scoring.scorer.RF_MODEL_PATH", rf_path)
    scorer = EventScorer(model_path=trained_artifact_path)
    db_path, test_get_session = _make_test_session(tmp_path)

    with patch("ml.scoring.scorer.get_session", test_get_session):
        scorer.score_and_persist(_make_process_create(), event_db_id=42)

    rows = _read_model_scores(db_path)
    rf_rows = [r for r in rows if r["model_type"] == "random_forest"]
    assert len(rf_rows) == 1
    rf_score = rf_rows[0]["score"]
    assert isinstance(rf_score, float)
    assert 0.0 <= rf_score <= 1.0


def test_rf_scoring_failure_is_non_fatal(
    trained_artifact_path: Path, tmp_path: Path, monkeypatch
) -> None:
    """Malformed _rf_artifact does not drop the IF score; only 1 row is written."""
    monkeypatch.setattr(
        "ml.scoring.scorer.RF_MODEL_PATH",
        tmp_path / "nonexistent.joblib",
    )
    scorer = EventScorer(model_path=trained_artifact_path)
    scorer._rf_artifact = {"malformed": True}
    db_path, test_get_session = _make_test_session(tmp_path)

    with patch("ml.scoring.scorer.get_session", test_get_session):
        score = scorer.score_and_persist(_make_process_create(), event_db_id=42)

    assert score is not None
    assert isinstance(score, float)
    rows = _read_model_scores(db_path)
    assert len(rows) == 1, f"Expected 1 model_scores row; got {len(rows)}"
    assert rows[0]["model_type"] == "isolation_forest"
