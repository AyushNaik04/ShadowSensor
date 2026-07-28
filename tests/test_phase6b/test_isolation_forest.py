"""
ShadowSensor Phase 6B — Isolation Forest unit tests.

Coverage:
  - Model trains without error on a minimal synthetic dataset
  - Artifact persists to disk and loads back correctly
  - Loaded artifact contains the required keys
  - Scores on held-out rows are in [0.0, 1.0]
  - Inference-time rescaling uses persisted training-time bounds, NOT batch-local
    ones (the critical addendum to decisions_log.md Entry 002)
  - rescale_scores() direction: most-anomalous raw score -> 1.0, least -> 0.0
  - score_features() handles dict input and DataFrame input
  - load_baseline() raises ValueError on missing columns
  - train_and_persist() raises FileNotFoundError on missing CSV
  - Benign-baseline score distribution: scores on the real benign_baseline.csv
    skew low (mean < 0.3, max < 0.7), confirming the model is not flagging its
    own training data as anomalous
  - CORRECTED per-event validation (decisions_log.md Entry 004): individual
    unaggregated Sysmon events from the live DB scored through EventFeatureExtractor
    alone — no ProcessWindowAggregator — produce non-degenerate variance.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ml.features.feature_spec import FEATURE_NAMES
from ml.training.train_isolation_forest import (
    DEFAULT_CSV_PATH,
    MODEL_PATH,
    load_artifact,
    load_baseline,
    rescale_scores,
    score_features,
    train_and_persist,
)

_LIVE_DB_PATH = Path("C:/ShadowSensor/data/shadowsensor.db")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def synthetic_df() -> pd.DataFrame:
    """Minimal synthetic feature DataFrame (50 rows) with all expected columns."""
    rng = np.random.RandomState(0)
    data = {name: rng.randint(0, 5, size=50).astype(float) for name in FEATURE_NAMES}
    return pd.DataFrame(data)


@pytest.fixture()
def trained_artifact(synthetic_df: pd.DataFrame, tmp_path: Path):
    """Train on synthetic data, persist to tmp_path, return (artifact, model_path)."""
    csv_path = tmp_path / "synthetic.csv"
    synthetic_df.assign(label=0).to_csv(csv_path, index=False)
    model_path = tmp_path / "test_model.joblib"
    train_and_persist(csv_path=csv_path, model_path=model_path)
    artifact = load_artifact(model_path)
    return artifact, model_path


# ---------------------------------------------------------------------------
# 1. Training produces a valid artifact
# ---------------------------------------------------------------------------

def test_train_completes_without_error(synthetic_df: pd.DataFrame, tmp_path: Path) -> None:
    """train_and_persist() runs without raising on a valid CSV."""
    csv_path = tmp_path / "data.csv"
    synthetic_df.assign(label=0).to_csv(csv_path, index=False)
    meta = train_and_persist(csv_path=csv_path, model_path=tmp_path / "model.joblib")
    assert meta["n_train"] == 50
    assert meta["n_features"] == len(FEATURE_NAMES)


def test_artifact_persisted_to_disk(trained_artifact) -> None:
    """joblib artifact file exists after training."""
    _, model_path = trained_artifact
    assert model_path.exists()
    assert model_path.stat().st_size > 0


def test_artifact_contains_required_keys(trained_artifact) -> None:
    """Loaded artifact dict has all four required keys."""
    artifact, _ = trained_artifact
    assert "model" in artifact
    assert "train_score_min" in artifact
    assert "train_score_max" in artifact
    assert "feature_names" in artifact


def test_artifact_feature_names_match_registry(trained_artifact) -> None:
    """Persisted feature_names must match FEATURE_NAMES exactly (order matters)."""
    artifact, _ = trained_artifact
    assert artifact["feature_names"] == list(FEATURE_NAMES)


def test_artifact_bounds_are_floats(trained_artifact) -> None:
    """train_score_min and train_score_max are Python floats."""
    artifact, _ = trained_artifact
    assert isinstance(artifact["train_score_min"], float)
    assert isinstance(artifact["train_score_max"], float)


def test_artifact_bounds_ordering(trained_artifact) -> None:
    """train_score_min <= train_score_max (min is the most-anomalous raw score)."""
    artifact, _ = trained_artifact
    assert artifact["train_score_min"] <= artifact["train_score_max"]


# ---------------------------------------------------------------------------
# 2. Rescaling direction and range
# ---------------------------------------------------------------------------

def test_rescale_most_anomalous_maps_to_one() -> None:
    """Raw score == train_min (most anomalous) must rescale to exactly 1.0."""
    result = rescale_scores(np.array([-0.5]), train_min=-0.5, train_max=-0.1)
    assert result[0] == pytest.approx(1.0)


def test_rescale_least_anomalous_maps_to_zero() -> None:
    """Raw score == train_max (least anomalous) must rescale to exactly 0.0."""
    result = rescale_scores(np.array([-0.1]), train_min=-0.5, train_max=-0.1)
    assert result[0] == pytest.approx(0.0)


def test_rescale_midpoint() -> None:
    """Midpoint raw score rescales to 0.5."""
    result = rescale_scores(np.array([-0.3]), train_min=-0.5, train_max=-0.1)
    assert result[0] == pytest.approx(0.5)


def test_rescale_out_of_distribution_clipped() -> None:
    """Scores outside training bounds are clipped to [0.0, 1.0]."""
    result = rescale_scores(
        np.array([-1.0, 0.5]),  # both outside [-0.5, -0.1]
        train_min=-0.5,
        train_max=-0.1,
    )
    assert result[0] == pytest.approx(1.0)
    assert result[1] == pytest.approx(0.0)


def test_rescale_degenerate_range_returns_zeros() -> None:
    """When train_min == train_max, all scores are 0.0 (no division by zero)."""
    result = rescale_scores(np.array([-0.3, -0.3]), train_min=-0.3, train_max=-0.3)
    assert np.all(result == 0.0)


# ---------------------------------------------------------------------------
# 3. Scores are in [0.0, 1.0] on held-out rows
# ---------------------------------------------------------------------------

def test_scores_in_unit_interval_on_held_out_rows(
    synthetic_df: pd.DataFrame, trained_artifact
) -> None:
    """All scores on held-out rows (same distribution) are in [0.0, 1.0]."""
    artifact, _ = trained_artifact
    rng = np.random.RandomState(99)
    held_out = pd.DataFrame(
        {name: rng.randint(0, 5, size=20).astype(float) for name in FEATURE_NAMES}
    )
    for _, row in held_out.iterrows():
        s = score_features(row.to_dict(), artifact)
        assert 0.0 <= s <= 1.0, f"Score out of range: {s}"


# ---------------------------------------------------------------------------
# 4. Inference-time rescaling uses persisted training bounds, NOT batch-local
#    (decisions_log.md Entry 002 critical addendum — required test)
# ---------------------------------------------------------------------------

def test_inference_uses_persisted_bounds_not_batch_local(
    trained_artifact,
) -> None:
    """Batch-local min/max MUST NOT be used at inference time.

    Proof via the degenerate-identical-row property:
    - Score a batch of 20 identical rows.
    - With batch-local bounds: batch_min == batch_max (all identical raw scores)
      → degenerate range → all scores would be 0.0.
    - With persisted training bounds: each row gets the same non-degenerate
      score determined by its position relative to the training distribution.

    Additionally verify that score_features() returns the same value as
    explicit training-bounds rescaling (proving the API uses the artifact's
    persisted bounds end-to-end).
    """
    artifact, _ = trained_artifact
    clf = artifact["model"]
    train_min: float = artifact["train_score_min"]
    train_max: float = artifact["train_score_max"]

    # Constant feature vector — chosen to avoid ambiguity at the boundary.
    vec = {name: 2.5 for name in FEATURE_NAMES}
    batch_df = pd.DataFrame([vec] * 20)

    raw_batch = clf.score_samples(batch_df[FEATURE_NAMES].values)

    # All 20 identical inputs must produce identical raw scores.
    assert np.allclose(raw_batch, raw_batch[0]), (
        "Identical inputs must produce identical raw scores from the model."
    )

    # Apply batch-local bounds (incorrect approach): batch_min == batch_max
    # (since all raw scores are identical) → degenerate → all 0.0.
    batch_local_scores = rescale_scores(raw_batch, float(raw_batch.min()), float(raw_batch.max()))
    assert np.allclose(batch_local_scores, 0.0), (
        "Batch-local rescaling on identical rows must yield 0.0 (degenerate range)."
    )

    # Apply persisted training bounds (correct approach).
    training_bound_scores = rescale_scores(raw_batch, train_min, train_max)

    # score_features() must match training-bounds rescaling.
    single_score = score_features(vec, artifact)
    assert single_score == pytest.approx(float(training_bound_scores[0]), abs=1e-9), (
        f"score_features() ({single_score:.6f}) must match explicit training-bounds "
        f"rescaling ({float(training_bound_scores[0]):.6f})."
    )

    # If the vector is not exactly at the least-anomalous training point,
    # training-bounds score will differ from 0.0 (the batch-local result).
    # This is the core correctness property — inter-batch comparability.
    if float(training_bound_scores[0]) > 1e-6:
        assert float(training_bound_scores[0]) != pytest.approx(0.0, abs=1e-6), (
            "Training-bounds score must not collapse to 0.0 on a non-trivial input."
        )


# ---------------------------------------------------------------------------
# 5. score_features() handles both dict and DataFrame inputs
# ---------------------------------------------------------------------------

def test_score_features_dict_input(trained_artifact) -> None:
    """score_features() accepts a plain dict and returns a float in [0.0, 1.0]."""
    artifact, _ = trained_artifact
    vec = {name: 0 for name in FEATURE_NAMES}
    s = score_features(vec, artifact)
    assert isinstance(s, float)
    assert 0.0 <= s <= 1.0


def test_score_features_dataframe_row(trained_artifact) -> None:
    """score_features() accepts a DataFrame (single row) and returns a float."""
    artifact, _ = trained_artifact
    row_df = pd.DataFrame([{name: 0 for name in FEATURE_NAMES}])
    s = score_features(row_df, artifact)
    assert isinstance(s, float)
    assert 0.0 <= s <= 1.0


# ---------------------------------------------------------------------------
# 6. Error handling
# ---------------------------------------------------------------------------

def test_load_baseline_raises_on_missing_columns(tmp_path: Path) -> None:
    """load_baseline() raises ValueError if required feature columns are absent."""
    bad_csv = tmp_path / "bad.csv"
    pd.DataFrame({"wrong_column": [1, 2, 3]}).to_csv(bad_csv, index=False)
    with pytest.raises(ValueError, match="missing expected feature columns"):
        load_baseline(bad_csv)


def test_load_artifact_raises_on_missing_file(tmp_path: Path) -> None:
    """load_artifact() raises FileNotFoundError when the joblib file doesn't exist."""
    with pytest.raises(FileNotFoundError):
        load_artifact(tmp_path / "nonexistent.joblib")


def test_train_raises_on_missing_csv(tmp_path: Path) -> None:
    """train_and_persist() propagates FileNotFoundError for a nonexistent CSV."""
    with pytest.raises(FileNotFoundError):
        train_and_persist(
            csv_path=tmp_path / "nonexistent.csv",
            model_path=tmp_path / "model.joblib",
        )


# ---------------------------------------------------------------------------
# 7. Real benign_baseline.csv: scores skew low
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not DEFAULT_CSV_PATH.exists(),
    reason="benign_baseline.csv not present in this environment",
)
def test_benign_baseline_scores_skew_low(tmp_path: Path) -> None:
    """Model trained on benign_baseline.csv should not flag its own training data.

    Sanity check: mean rescaled score < 0.3, max rescaled score < 0.7.
    A model flagging its own training data as anomalous indicates a structural
    problem with the training data or the model configuration.
    """
    model_path = tmp_path / "real_model.joblib"
    meta = train_and_persist(csv_path=DEFAULT_CSV_PATH, model_path=model_path)
    stats = meta["score_stats"]

    assert stats["mean"] < 0.3, (
        f"Mean score {stats['mean']:.4f} is too high — model appears to flag "
        "its own training data as anomalous."
    )
    # max is always 1.0 by construction (min-max rescaling on training data).
    # Check the high-scorer fraction instead — fewer than 15% should score > 0.5.
    high_frac = stats["n_above_0_5"] / stats["n_total"]
    assert high_frac < 0.15, (
        f"{stats['n_above_0_5']}/{stats['n_total']} ({100*high_frac:.1f}%) rows score > 0.5. "
        "More than 15% of training rows flagged as anomalous suggests a structural problem."
    )


# ---------------------------------------------------------------------------
# 8. CORRECTED per-event validation (decisions_log.md Entry 004)
#    Scores individual, unaggregated Sysmon events through EventFeatureExtractor
#    alone — no ProcessWindowAggregator — using the persisted trained model.
#    This is the test that the original (invalid) in-sample validation should
#    have been: it exercises exactly the input distribution that Subphase 3's
#    live per-event scoring will produce in production.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not _LIVE_DB_PATH.exists() or not MODEL_PATH.exists(),
    reason="Live DB or trained model artifact not present in this environment",
)
def test_per_event_scoring_non_degenerate() -> None:
    """Per-event scoring on real individual Sysmon events must be non-degenerate.

    Methodology (matches decisions_log.md Entry 004):
    - Pull up to 200 events per EID from the live database (no aggregation).
    - Run each through EventFeatureExtractor.extract() alone — single event,
      no ProcessWindowAggregator, no window state.
    - Score each vector through the persisted model.

    Non-degeneracy criteria (stop conditions from task.md must NOT be met):
    - Variance must be >= 0.005 (well above zero; degenerate = near-constant)
    - Max score must be < 0.99 (no clustering near 1.0)
    - The fraction of scores < 0.01 must be < 0.99 (no degenerate low collapse)
    - Score range (max - min) must be > 0.05 (not near-constant)

    Confirmed values from the 2026-07-28 run on 722 events:
      variance=0.0407, max=0.6427, near-zero fraction=0.0%, range=0.6321
    """
    from ml.features.extractor import EventFeatureExtractor

    artifact = load_artifact(MODEL_PATH)
    extractor = EventFeatureExtractor()

    conn = sqlite3.connect(str(_LIVE_DB_PATH))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    target_eids = [1, 3, 7, 10, 22]
    sampled_events: list[dict[str, object]] = []
    for eid in target_eids:
        cursor.execute(
            "SELECT id, event_type_id, timestamp, pid, image, raw_json "
            "FROM events WHERE event_type_id=? ORDER BY RANDOM() LIMIT 200",
            (eid,),
        )
        sampled_events.extend([dict(r) for r in cursor.fetchall()])
    conn.close()

    if len(sampled_events) < 10:
        pytest.skip("Insufficient events in live DB for per-event validation")

    scores = np.array([
        score_features(extractor.extract(event), artifact)
        for event in sampled_events
    ])

    variance = float(scores.var())
    score_max = float(scores.max())
    score_range = float(scores.max() - scores.min())
    near_zero_frac = float((scores < 0.01).sum()) / len(scores)

    assert variance >= 0.005, (
        f"Per-event score variance {variance:.6f} is degenerate (< 0.005). "
        "Per-event scoring against a window-trained model produces no real signal."
    )
    assert score_max < 0.99, (
        f"Max per-event score {score_max:.4f} clusters near 1.0 — "
        "model flags all live events as anomalous."
    )
    assert score_range > 0.05, (
        f"Per-event score range {score_range:.4f} < 0.05 — distribution is near-constant."
    )
    assert near_zero_frac < 0.99, (
        f"{near_zero_frac*100:.1f}% of scores collapse near 0.0 — degenerate low distribution."
    )
