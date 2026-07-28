"""Phase 5 process-window feature extraction pipeline."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from ml.features.aggregator import ProcessWindowAggregator
from ml.features.extractor import EventFeatureExtractor


WindowKey = tuple[str | None, int | str]


_BOUND_FORMATS = (
    ("%Y-%m-%d %H:%M:%S.%f", True),
    ("%Y-%m-%d %H:%M:%S", False),
    ("%Y-%m-%dT%H:%M:%S.%f", True),
    ("%Y-%m-%dT%H:%M:%S", False),
)


def parse_time_bound(raw: str, *, bound_name: str) -> str:
    """Parse a CLI/API time bound into a TEXT value comparable to events.timestamp.

    Stored timestamps are 'YYYY-MM-DD HH:MM:SS.ffffff' (space separator, six-digit
    zero-padded microseconds). ISO-8601 'T' separators are normalized to space.

    Padding rule (asymmetry is intentional):
    - --until WITHOUT a fractional/microsecond component (plain
      'YYYY-MM-DD HH:MM:SS' or '...THH:MM:SS') is padded to '.999999' so inclusive
      ``timestamp <= until`` still includes every stored event within that whole
      second under lexicographic TEXT comparison.
    - --until WITH an explicit fractional component is used exactly as parsed
      (formatted to six-digit microseconds); NO .999999 padding is applied.
    - --since is never padded; a whole-second since binds as 'YYYY-MM-DD HH:MM:SS'
      (lexicographic ``>=`` already includes '...SS.ffffff' rows in that second).
    """
    text = raw.strip()
    parsed: datetime | None = None
    matched_with_fraction = False
    for fmt, has_fraction in _BOUND_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
            matched_with_fraction = has_fraction
            break
        except ValueError:
            continue
    if parsed is None:
        raise ValueError(
            f"Invalid {bound_name} value {raw!r}: expected "
            "YYYY-MM-DD HH:MM:SS[.ffffff] or YYYY-MM-DDTHH:MM:SS[.ffffff]"
        )

    # Pad .999999 ONLY for --until when the user supplied no fractional component.
    if bound_name == "--until" and not matched_with_fraction:
        return parsed.strftime("%Y-%m-%d %H:%M:%S") + ".999999"
    if matched_with_fraction:
        # Explicit fractional --until/--since: use exactly the parsed instant
        # (six-digit %f); do not apply whole-second padding.
        return parsed.strftime("%Y-%m-%d %H:%M:%S.%f")
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def _time_filter_sql(
    time_from: str | None,
    time_to: str | None,
) -> tuple[str, tuple[str, ...]]:
    """Return (optional WHERE clause including leading newline, bind params)."""
    clauses: list[str] = []
    params: list[str] = []
    if time_from is not None:
        clauses.append("timestamp >= ?")
        params.append(time_from)
    if time_to is not None:
        clauses.append("timestamp <= ?")
        params.append(time_to)
    if not clauses:
        return "", ()
    return "\nWHERE " + " AND ".join(clauses), tuple(params)


class FeatureExtractionPipeline:
    """Read events/rule_hits from SQLite and emit per-window feature vectors."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path) if not isinstance(db_path, Path) else db_path

    def run(
        self,
        label: int | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
    ) -> list[dict]:
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
                events_where, events_params = _time_filter_sql(time_from, time_to)
                event_rows = conn.execute(
                    "SELECT id, event_type_id, timestamp, pid, image, raw_json, ingested_at\n"
                    "FROM events"
                    f"{events_where}\n"
                    "ORDER BY timestamp ASC",
                    events_params,
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
                hits_where, hits_params = _time_filter_sql(time_from, time_to)
                rule_hit_rows = conn.execute(
                    "SELECT id, event_fk, rule_id, timestamp\n"
                    "FROM rule_hits"
                    f"{hits_where}\n"
                    "ORDER BY timestamp ASC",
                    hits_params,
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
