"""
ShadowSensor Phase 6B — ML Insights Service

Queries model_scores and the trained model artifact to provide data for
the /dashboard/ml-insights page.  All functions are read-only; they never
load the joblib model weights — only stat the artifact file for mtime.

Architecture note: training_date is derived from the artifact file's mtime
because the joblib artifact dict does not contain a training timestamp.
This is sufficient for display purposes and requires no schema changes.
"""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from ml.training.train_isolation_forest import MODEL_PATH
from storage.database import get_session
from storage.models import ModelScoreRecord


# 10 equal-width brackets covering [0.0, 1.0].
# Upper bound of the last bracket is 1.01 so that score == 1.0 is included.
_SCORE_BRACKETS: list[tuple[str, float, float]] = [
    ("0.0–0.1", 0.0, 0.1),
    ("0.1–0.2", 0.1, 0.2),
    ("0.2–0.3", 0.2, 0.3),
    ("0.3–0.4", 0.3, 0.4),
    ("0.4–0.5", 0.4, 0.5),
    ("0.5–0.6", 0.5, 0.6),
    ("0.6–0.7", 0.6, 0.7),
    ("0.7–0.8", 0.7, 0.8),
    ("0.8–0.9", 0.8, 0.9),
    ("0.9–1.0", 0.9, 1.01),
]


def _artifact_training_date(model_path: Path) -> Optional[str]:
    """Return artifact mtime as 'YYYY-MM-DD HH:MM UTC', or None if absent."""
    if not model_path.exists():
        return None
    mtime = model_path.stat().st_mtime
    return datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def get_isolation_forest_status(model_path: Path = MODEL_PATH) -> dict[str, Any]:
    """Return Isolation Forest status and all-time score distribution.

    Reads every model_scores row with model_type='isolation_forest' and
    computes summary statistics in Python.  Suitable for page loads on a
    host with up to ~100k scored events; no batching required at current
    data volumes.

    Args:
        model_path: path to the persisted joblib artifact (default: production path).

    Returns:
        Dict with keys:
          trained (bool)           — True if any scored rows exist
          training_date (str|None) — artifact mtime formatted string, or None
          total_scored (int)       — count of model_scores rows
          score_min (float|None)
          score_max (float|None)
          score_mean (float|None)
          score_median (float|None)
          brackets (list[dict])    — 10 dicts with range/count/pct keys
    """
    with get_session() as session:
        rows = (
            session.query(ModelScoreRecord.score)
            .filter(ModelScoreRecord.model_type == "isolation_forest")
            .all()
        )

    scores = [r.score for r in rows]
    training_date = _artifact_training_date(model_path)

    if not scores:
        return {
            "trained": False,
            "training_date": training_date,
            "total_scored": 0,
            "score_min": None,
            "score_max": None,
            "score_mean": None,
            "score_median": None,
            "brackets": [],
        }

    total = len(scores)
    bracket_data: list[dict[str, Any]] = []
    for label, lo, hi in _SCORE_BRACKETS:
        count = sum(1 for s in scores if lo <= s < hi)
        bracket_data.append(
            {
                "range": label,
                "count": count,
                "pct": round(100.0 * count / total, 1),
            }
        )

    return {
        "trained": True,
        "training_date": training_date,
        "total_scored": total,
        "score_min": round(min(scores), 4),
        "score_max": round(max(scores), 4),
        "score_mean": round(sum(scores) / total, 4),
        "score_median": round(statistics.median(scores), 4),
        "brackets": bracket_data,
    }


def get_score_trend(
    hours: int = 24,
    model_path: Path = MODEL_PATH,
) -> list[dict[str, Any]]:
    """Return hourly-averaged Isolation Forest scores for the last *hours* hours.

    Only rows whose timestamp falls within the window are included.
    Buckets with zero rows are omitted (sparse output — the chart fills gaps).

    Returns:
        List of dicts sorted ascending by hour:
          [{"hour": "2026-07-28T10:00", "avg_score": 0.34, "count": 120}, ...]
        Empty list if no scored events exist in the window.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    with get_session() as session:
        rows = (
            session.query(ModelScoreRecord.score, ModelScoreRecord.timestamp)
            .filter(
                ModelScoreRecord.model_type == "isolation_forest",
                ModelScoreRecord.timestamp >= start,
            )
            .order_by(ModelScoreRecord.timestamp.asc())
            .all()
        )

    hourly: dict[str, list[float]] = {}
    for score, ts in rows:
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        bucket = ts.strftime("%Y-%m-%dT%H:00")
        hourly.setdefault(bucket, []).append(score)

    return [
        {
            "hour": hour,
            "avg_score": round(sum(v) / len(v), 4),
            "count": len(v),
        }
        for hour, v in sorted(hourly.items())
    ]
