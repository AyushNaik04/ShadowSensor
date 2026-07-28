"""
ShadowSensor Phase 6B — Real-Time Isolation Forest Scorer

Loads the persisted Isolation Forest artifact ONCE at construction time and
scores individual Sysmon events, writing results to model_scores.

Design decisions in effect (see docs/decisions_log.md):
  Entry 002 — continuous score via score_samples(), persisted training-time
              bounds; never batch-local rescaling.
  Entry 003 — per-event scoring (no ProcessWindowAggregator); scoring hook
              calls persist_pipeline_event directly so the event DB id is
              available for model_scores.event_fk.
  Entry 004 — empirically validated: per-event scoring is non-degenerate on
              722 real Sysmon events (variance=0.0407).

Error-handling contract (hard requirement inherited from Phase 6A):
  All failure paths MUST produce a visible log line. Silent exception
  swallowing is explicitly forbidden — it was the root cause of Phase 6A's
  15-day data-loss bug. Each step (event conversion, feature extraction,
  model scoring, DB write) is wrapped in its own try/except with logger.error.
"""
from __future__ import annotations

import dataclasses
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ml.features.extractor import EventFeatureExtractor
from ml.training.train_isolation_forest import MODEL_PATH, load_artifact, score_features
from storage.database import get_session
from storage.models import ModelScoreRecord

logger = logging.getLogger(__name__)

# Mirrors StorageWriter._event_type_map / _image_map.
# storage_writer.py is frozen — import from it is avoided; this minimal
# copy is the single source of truth for the scoring path.
_EID_MAP: dict[str, int] = {
    "ProcessCreateEvent": 1,
    "NetworkConnectEvent": 3,
    "ImageLoadEvent": 7,
    "CreateRemoteThreadEvent": 8,
    "OpenProcessEvent": 10,
    "DnsQueryEvent": 22,
}
_IMAGE_MAP: dict[str, str] = {
    "ProcessCreateEvent": "image",
    "NetworkConnectEvent": "image",
    "ImageLoadEvent": "image",
    "CreateRemoteThreadEvent": "source_image",
    "OpenProcessEvent": "source_image",
    "DnsQueryEvent": "image",
}


def _event_to_extractor_row(event: Any) -> dict[str, Any]:
    """Convert a pipeline event dataclass to the dict EventFeatureExtractor expects.

    The extractor (ml/features/extractor.py) reads from a dict that mirrors
    the events table row: event_type_id, timestamp, image, raw_json.

    Raises:
        TypeError: if event is not a dataclass.
    """
    if not dataclasses.is_dataclass(event):
        raise TypeError(
            f"Expected a dataclass event for scoring; got {type(event).__name__!r}"
        )

    class_name = type(event).__name__
    eid = _EID_MAP.get(class_name) or getattr(event, "event_id", None)
    image_attr = _IMAGE_MAP.get(class_name, "")
    image = getattr(event, image_attr, None) if image_attr else None
    timestamp = getattr(event, "utc_time", None)
    raw_json = json.dumps(dataclasses.asdict(event), default=str)

    return {
        "event_type_id": eid,
        "timestamp": timestamp,
        "image": image,
        "raw_json": raw_json,
    }


def _coerce_event_timestamp(event: Any) -> datetime:
    """Extract event timestamp for model_scores.timestamp; fall back to UTC now."""
    raw = getattr(event, "utc_time", None)
    if raw is None:
        return datetime.now(UTC)
    if isinstance(raw, datetime):
        return raw
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(UTC)


class EventScorer:
    """Load the Isolation Forest artifact once and score individual Sysmon events.

    The artifact (model + training-time bounds) is loaded from disk in
    __init__ and kept in memory for the lifetime of the scorer. All
    score_and_persist() calls use these in-memory bounds — never reload
    from disk or recompute bounds from the current batch.

    Thread-safety note: sklearn's IsolationForest.score_samples() is
    read-only and safe to call from a single thread. The pipeline's
    on_event callback is single-threaded, so no locking is required.
    """

    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        """Load and validate the persisted model artifact.

        Raises:
            FileNotFoundError: if model_path does not exist.
        """
        self._artifact = load_artifact(model_path)
        self._extractor = EventFeatureExtractor()
        logger.info(
            "[scorer] Isolation Forest loaded from %s "
            "(train_score_min=%.6f, train_score_max=%.6f, features=%d)",
            model_path,
            self._artifact["train_score_min"],
            self._artifact["train_score_max"],
            len(self._artifact["feature_names"]),
        )

    def score_and_persist(
        self,
        event: Any,
        event_db_id: int | None,
    ) -> float | None:
        """Score a single event and write the result to model_scores.

        Each failure path produces a visible logger.error line — never
        silently swallowed (Phase 6A lesson).

        Args:
            event: Pipeline event dataclass (ProcessCreateEvent, etc.).
            event_db_id: events.id FK for the model_scores row. When None,
                the score is computed but not written to the DB.

        Returns:
            Anomaly score in [0.0, 1.0] where higher = more anomalous,
            or None if feature extraction or model scoring failed.
            A DB write failure still returns the score (computed value is
            valid; only persistence failed).
        """
        # Step 1 — convert pipeline event dataclass to extractor dict format.
        try:
            event_row = _event_to_extractor_row(event)
        except Exception as exc:
            logger.error(
                "[scorer] Event-to-row conversion failed [%s]: %s",
                type(exc).__name__,
                exc,
                exc_info=True,
            )
            return None

        # Step 2 — extract the 30-feature vector via EventFeatureExtractor.
        try:
            features = self._extractor.extract(event_row)
        except Exception as exc:
            logger.error(
                "[scorer] Feature extraction failed [%s]: %s",
                type(exc).__name__,
                exc,
                exc_info=True,
            )
            return None

        # Step 3 — score using persisted training-time bounds (Entry 002).
        try:
            score = score_features(features, self._artifact)
        except Exception as exc:
            logger.error(
                "[scorer] Model scoring failed [%s]: %s",
                type(exc).__name__,
                exc,
                exc_info=True,
            )
            return None

        # Step 4 — persist to model_scores (only when event_db_id is known).
        if event_db_id is not None:
            ts = _coerce_event_timestamp(event)
            try:
                with get_session() as session:
                    record = ModelScoreRecord(
                        event_fk=event_db_id,
                        model_type="isolation_forest",
                        score=score,
                        timestamp=ts,
                    )
                    session.add(record)
                    session.flush()
            except Exception as exc:
                logger.error(
                    "[scorer] model_scores DB write failed (non-fatal) [%s]: %s",
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )
                # Score was computed successfully — return it even if persistence
                # failed.  The caller can decide whether to retry or log further.

        return score
