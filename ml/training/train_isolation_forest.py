"""
ShadowSensor Phase 6B — Isolation Forest Training

Trains an Isolation Forest on benign_baseline.csv and persists the model
together with training-time rescaling bounds as a single joblib artifact at
ml/models/isolation_forest.joblib.

Rescaling design (decisions_log.md Entry 002):
  score_samples() returns raw anomaly scores where MORE NEGATIVE = MORE ANOMALOUS.
  Rescaled score formula: score = (train_max - raw) / (train_max - train_min)
    raw = train_min (most anomalous) -> 1.0
    raw = train_max (least anomalous) -> 0.0
  train_min and train_max are computed ONCE from the training data and persisted.
  All future scoring (including the live pipeline) MUST use these fixed bounds —
  never recompute min/max from whatever batch is currently being scored.

See docs/decisions_log.md Entry 001 (contamination='auto') and Entry 002
(continuous score, persisted bounds).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ml.features.feature_spec import FEATURE_NAMES

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MODEL_PATH = _REPO_ROOT / "ml" / "models" / "isolation_forest.joblib"
DEFAULT_CSV_PATH = _REPO_ROOT / "data" / "features" / "benign_baseline.csv"


def load_baseline(csv_path: Path) -> pd.DataFrame:
    """Load benign_baseline.csv, validate columns, return feature-only DataFrame.

    Drops the label column; IsolationForest is unsupervised and does not use it.
    Raises ValueError if expected feature columns are missing.
    """
    df = pd.read_csv(csv_path)
    missing = [col for col in FEATURE_NAMES if col not in df.columns]
    if missing:
        raise ValueError(f"CSV missing expected feature columns: {missing}")
    return df[FEATURE_NAMES].copy()


def rescale_scores(
    raw: np.ndarray,
    train_min: float,
    train_max: float,
) -> np.ndarray:
    """Rescale raw score_samples() output to [0.0, 1.0] with higher = more anomalous.

    Uses training-time bounds (train_min, train_max) — never batch-local values.
    Out-of-distribution inputs that fall outside the training range are clipped.
    """
    if train_max == train_min:
        return np.zeros_like(raw, dtype=float)
    scaled = (train_max - raw) / (train_max - train_min)
    return np.clip(scaled, 0.0, 1.0)


def feature_permutation_importance(
    clf: IsolationForest,
    X: pd.DataFrame,
    n_repeats: int = 10,
    random_state: int = 42,
) -> dict[str, float]:
    """Estimate per-feature importance via permutation on score_samples().

    For each feature: shuffle its values, re-score all rows, measure mean change
    in raw anomaly score vs. the unpermuted baseline.

    A negative mean_delta means permuting the feature made the model assign LOWER
    (more anomalous) scores on average — the feature's real values contributed to
    the model recognising these rows as normal. A large negative value = high
    importance for normality detection.

    Returns a dict mapping feature_name -> mean_delta (mean_permuted - mean_base),
    sorted ascending (most important first by magnitude of negative delta).
    """
    rng = np.random.RandomState(random_state)
    base_scores = clf.score_samples(X)
    base_mean = float(base_scores.mean())

    importances: dict[str, float] = {}
    X_arr = X.values.copy()
    for i, col in enumerate(X.columns):
        deltas = []
        for _ in range(n_repeats):
            X_perm = X_arr.copy()
            X_perm[:, i] = rng.permutation(X_perm[:, i])
            perm_df = pd.DataFrame(X_perm, columns=X.columns)
            perm_mean = float(clf.score_samples(perm_df).mean())
            deltas.append(perm_mean - base_mean)
        importances[col] = float(np.mean(deltas))

    return dict(sorted(importances.items(), key=lambda kv: kv[1]))


def train_and_persist(
    csv_path: Path = DEFAULT_CSV_PATH,
    model_path: Path = MODEL_PATH,
    random_state: int = 42,
    n_repeats_importance: int = 10,
) -> dict[str, Any]:
    """Train Isolation Forest, persist artifact, return training metadata.

    The persisted joblib file contains a dict with keys:
      'model'           : fitted IsolationForest
      'train_score_min' : float — minimum raw score_samples() value on training data
      'train_score_max' : float — maximum raw score_samples() value on training data
      'feature_names'   : list[str] — feature column order (must match at inference)

    Returns a metadata dict suitable for logging and reporting.
    """
    logger.info("[train] Loading baseline CSV: %s", csv_path)
    X = load_baseline(csv_path)
    logger.info("[train] Loaded %d rows, %d features", len(X), X.shape[1])

    # Train — contamination='auto', all other hyperparameters at sklearn defaults.
    # See decisions_log.md Entry 001 for rationale.
    clf = IsolationForest(contamination="auto", random_state=random_state)
    clf.fit(X)
    logger.info(
        "[train] IsolationForest fitted: n_estimators=%d, max_samples=%s",
        clf.n_estimators,
        clf.max_samples_,
    )

    # Compute training-time rescaling bounds (MUST be persisted — see Entry 002).
    raw_scores: np.ndarray = clf.score_samples(X)
    train_min = float(raw_scores.min())
    train_max = float(raw_scores.max())
    logger.info("[train] Raw score range: min=%.6f  max=%.6f", train_min, train_max)

    # Score benign baseline with persisted bounds.
    rescaled = rescale_scores(raw_scores, train_min, train_max)
    score_stats = {
        "min": float(rescaled.min()),
        "max": float(rescaled.max()),
        "mean": float(rescaled.mean()),
        "median": float(np.median(rescaled)),
        "std": float(rescaled.std()),
        "n_above_0_5": int((rescaled > 0.5).sum()),
        "n_total": int(len(rescaled)),
    }
    logger.info(
        "[train] Rescaled score distribution — min=%.4f  max=%.4f  mean=%.4f  median=%.4f  std=%.4f",
        score_stats["min"], score_stats["max"],
        score_stats["mean"], score_stats["median"], score_stats["std"],
    )
    logger.info(
        "[train] Rows scoring > 0.5 (anomalous): %d / %d (%.1f%%)",
        score_stats["n_above_0_5"],
        score_stats["n_total"],
        100.0 * score_stats["n_above_0_5"] / score_stats["n_total"],
    )

    # Feature-contribution sanity check.
    logger.info("[train] Running permutation importance (%d repeats)...", n_repeats_importance)
    importance = feature_permutation_importance(clf, X, n_repeats=n_repeats_importance, random_state=random_state)

    caveat_features = ["open_process_suspicious_access", "hour_of_day", "is_off_hours"]
    logger.info("[train] Permutation importance (sorted ascending, most impactful first):")
    for feat, delta in importance.items():
        marker = " <-- CAVEAT FEATURE" if feat in caveat_features else ""
        logger.info("  %-40s  mean_delta=% .6f%s", feat, delta, marker)

    # Persist model + bounds together.
    model_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": clf,
        "train_score_min": train_min,
        "train_score_max": train_max,
        "feature_names": list(FEATURE_NAMES),
    }
    joblib.dump(artifact, model_path)
    logger.info("[train] Artifact persisted: %s", model_path)

    return {
        "model_path": str(model_path),
        "n_train": len(X),
        "n_features": X.shape[1],
        "train_score_min": train_min,
        "train_score_max": train_max,
        "score_stats": score_stats,
        "permutation_importance": importance,
    }


def load_artifact(model_path: Path = MODEL_PATH) -> dict[str, Any]:
    """Load and return the persisted model artifact dict.

    Expected keys: 'model', 'train_score_min', 'train_score_max', 'feature_names'.
    Raises FileNotFoundError if the artifact does not exist.
    """
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model artifact not found: {model_path}. "
            "Run train_and_persist() first."
        )
    return joblib.load(model_path)


def score_features(
    feature_vector: dict[str, Any] | pd.DataFrame,
    artifact: dict[str, Any],
) -> float:
    """Score a single feature vector (or DataFrame row) using the persisted artifact.

    Always uses the training-time bounds from the artifact — never recomputes.
    Returns a float in [0.0, 1.0] where higher = more anomalous.
    """
    clf: IsolationForest = artifact["model"]
    train_min: float = artifact["train_score_min"]
    train_max: float = artifact["train_score_max"]
    feature_names: list[str] = artifact["feature_names"]

    if isinstance(feature_vector, dict):
        row = pd.DataFrame([[feature_vector.get(f, 0) for f in feature_names]], columns=feature_names)
    else:
        row = feature_vector[feature_names].iloc[:1]

    raw = clf.score_samples(row)
    return float(rescale_scores(raw, train_min, train_max)[0])


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    csv_arg = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CSV_PATH
    out_arg = Path(sys.argv[2]) if len(sys.argv) > 2 else MODEL_PATH

    meta = train_and_persist(csv_path=csv_arg, model_path=out_arg)
    print(f"\nArtifact saved to: {meta['model_path']}")
    print(f"Training rows: {meta['n_train']}")
    print(f"Score distribution: {meta['score_stats']}")
