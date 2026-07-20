"""Phase 5 process-window feature extraction pipeline."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from ml.features.aggregator import ProcessWindowAggregator
from ml.features.extractor import EventFeatureExtractor


WindowKey = tuple[str | None, int | str]


class FeatureExtractionPipeline:
    """Read events/rule_hits from SQLite and emit per-window feature vectors."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path) if not isinstance(db_path, Path) else db_path

    def run(self, label: int | None = None) -> list[dict]:
        db_path_str = str(self.db_path)
        if db_path_str != ":memory:" and not self.db_path.exists():
            return []

        try:
            conn = sqlite3.connect(db_path_str)
        except sqlite3.Error:
            return []

        conn.row_factory = sqlite3.Row
        try:
            try:
                event_rows = conn.execute(
                    """
                    SELECT id, event_type_id, timestamp, pid, image, raw_json, ingested_at
                    FROM events
                    ORDER BY timestamp ASC
                    """
                ).fetchall()
            except sqlite3.OperationalError:
                return []

            if not event_rows:
                return []

            windows: dict[WindowKey, list[dict]] = {}
            event_id_to_window: dict[int, WindowKey] = {}

            for row in event_rows:
                event = dict(row)
                pid = event.get("pid")
                window_key: WindowKey = (event.get("image"), "null_pid" if pid is None else pid)
                windows.setdefault(window_key, []).append(event)
                event_id = event.get("id")
                if event_id is not None:
                    event_id_to_window[int(event_id)] = window_key

            window_rule_hits: dict[WindowKey, list[dict]] = {key: [] for key in windows}
            try:
                rule_hit_rows = conn.execute(
                    """
                    SELECT id, event_fk, rule_id, timestamp
                    FROM rule_hits
                    ORDER BY timestamp ASC
                    """
                ).fetchall()
            except sqlite3.OperationalError:
                rule_hit_rows = []

            for row in rule_hit_rows:
                rule_hit = dict(row)
                event_fk = rule_hit.get("event_fk")
                if event_fk is None:
                    continue
                window_key = event_id_to_window.get(int(event_fk))
                if window_key is None:
                    continue
                window_rule_hits[window_key].append(rule_hit)

            extractor = EventFeatureExtractor()
            aggregator = ProcessWindowAggregator()
            results: list[dict] = []

            for window_key, window_events in windows.items():
                event_vectors = [
                    (int(event["event_type_id"]), extractor.extract(event))
                    for event in window_events
                ]
                aggregated = aggregator.aggregate(
                    event_vectors,
                    window_rule_hits.get(window_key, []),
                )
                if label is not None:
                    aggregated["label"] = int(label)
                results.append(aggregated)

            return results
        finally:
            conn.close()
