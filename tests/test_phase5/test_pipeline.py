"""Tests for Phase 5 pipeline orchestration and CSV export."""

from __future__ import annotations

import csv
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from ml.features.exporter import export_to_csv
from ml.features.pipeline import FeatureExtractionPipeline, parse_time_bound

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_EXE = REPO_ROOT / "python_runtime" / "python.exe"
if not PYTHON_EXE.exists():
    PYTHON_EXE = Path(sys.executable)


def create_test_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            pid INTEGER NULL,
            image TEXT NULL,
            raw_json TEXT NOT NULL,
            ingested_at TEXT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE rule_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_fk INTEGER NULL,
            rule_id TEXT NULL,
            timestamp TEXT NOT NULL
        )
        """
    )
    conn.commit()


def _insert_event(
    conn: sqlite3.Connection,
    event_type_id: int,
    timestamp: str,
    pid: int | None,
    image: str,
    raw_json: dict | None = None,
) -> int:
    payload = raw_json or {}
    cur = conn.execute(
        """
        INSERT INTO events (event_type_id, timestamp, pid, image, raw_json, ingested_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            event_type_id,
            timestamp,
            pid,
            image,
            json.dumps(payload),
            "2026-07-14T00:00:00",
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def _insert_rule_hit(
    conn: sqlite3.Connection,
    event_fk: int | None,
    rule_id: str,
    timestamp: str,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO rule_hits (event_fk, rule_id, timestamp)
        VALUES (?, ?, ?)
        """,
        (event_fk, rule_id, timestamp),
    )
    conn.commit()
    return int(cur.lastrowid)


def _run_pipeline_with_memory_db(
    conn: sqlite3.Connection,
    monkeypatch,
    label: int | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
) -> list[dict]:
    import ml.features.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module.sqlite3, "connect", lambda _: conn)
    pipeline = FeatureExtractionPipeline(":memory:")
    return pipeline.run(label=label, time_from=time_from, time_to=time_to)


def _seed_three_timed_windows(conn: sqlite3.Connection) -> None:
    """Three distinct process windows at production-like microsecond timestamps."""
    _insert_event(
        conn, 1, "2026-07-14 09:00:00.000000", 100, r"C:\Windows\System32\early.exe"
    )
    _insert_event(
        conn, 1, "2026-07-14 10:00:00.000000", 200, r"C:\Windows\System32\mid.exe"
    )
    _insert_event(
        conn, 1, "2026-07-14 11:00:00.000000", 300, r"C:\Windows\System32\late.exe"
    )


def test_empty_db_returns_empty_list(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    result = _run_pipeline_with_memory_db(conn, monkeypatch)
    assert result == []


def test_single_eid1_event_produces_one_window(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _insert_event(conn, 1, "2026-07-14T10:00:00", 1234, r"C:\Windows\System32\cmd.exe")
    result = _run_pipeline_with_memory_db(conn, monkeypatch)
    assert len(result) == 1


def test_two_events_same_process_one_window(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _insert_event(conn, 1, "2026-07-14T10:00:00", 1234, r"C:\Windows\System32\cmd.exe")
    _insert_event(conn, 3, "2026-07-14T10:00:01", 1234, r"C:\Windows\System32\cmd.exe")
    result = _run_pipeline_with_memory_db(conn, monkeypatch)
    assert len(result) == 1


def test_two_events_different_process_two_windows(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _insert_event(conn, 1, "2026-07-14T10:00:00", 1234, r"C:\Windows\System32\cmd.exe")
    _insert_event(conn, 1, "2026-07-14T10:00:01", 5555, r"C:\Windows\System32\notepad.exe")
    result = _run_pipeline_with_memory_db(conn, monkeypatch)
    assert len(result) == 2


def test_label_none_no_label_key(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _insert_event(conn, 1, "2026-07-14T10:00:00", 1234, r"C:\Windows\System32\cmd.exe")
    result = _run_pipeline_with_memory_db(conn, monkeypatch, label=None)
    assert len(result) == 1
    assert "label" not in result[0]


def test_label_zero_adds_label_key(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _insert_event(conn, 1, "2026-07-14T10:00:00", 1234, r"C:\Windows\System32\cmd.exe")
    result = _run_pipeline_with_memory_db(conn, monkeypatch, label=0)
    assert result[0]["label"] == 0


def test_label_one_adds_label_key(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _insert_event(conn, 1, "2026-07-14T10:00:00", 1234, r"C:\Windows\System32\cmd.exe")
    result = _run_pipeline_with_memory_db(conn, monkeypatch, label=1)
    assert result[0]["label"] == 1


def test_rule_hits_joined_via_event_fk(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    event_id = _insert_event(conn, 1, "2026-07-14T10:00:00", 1234, r"C:\Windows\System32\cmd.exe")
    _insert_rule_hit(conn, event_id, "PS_ENCODED_CMD_001", "2026-07-14T11:00:00")
    _insert_rule_hit(conn, event_id, "LOLBIN_MSHTA_001", "2026-07-14T11:05:00")
    result = _run_pipeline_with_memory_db(conn, monkeypatch)
    assert len(result) == 1
    assert result[0]["rule_hit_count"] == 2


def test_rule_hit_with_unmatched_event_fk_is_skipped(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _insert_event(conn, 1, "2026-07-14T10:00:00", 1234, r"C:\Windows\System32\cmd.exe")
    _insert_rule_hit(conn, 999999, "PS_ENCODED_CMD_001", "2026-07-14T11:00:00")
    result = _run_pipeline_with_memory_db(conn, monkeypatch)
    assert len(result) == 1
    assert result[0]["rule_hit_count"] == 0


def test_null_pid_does_not_crash(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _insert_event(conn, 1, "2026-07-14T10:00:00", None, r"C:\Windows\System32\cmd.exe")
    result = _run_pipeline_with_memory_db(conn, monkeypatch)
    assert len(result) == 1


def test_export_to_csv_creates_file(tmp_path):
    output_path = tmp_path / "features.csv"
    export_to_csv([{"cmd_length": 10}], output_path, label=None)
    assert output_path.exists()


def test_export_to_csv_empty_vectors_writes_header_only(tmp_path):
    output_path = tmp_path / "empty_features.csv"
    export_to_csv([], output_path, label=None)
    rows = list(csv.reader(output_path.open(newline="", encoding="utf-8")))
    assert len(rows) == 1


def test_export_csv_column_count_without_label(tmp_path):
    output_path = tmp_path / "features_no_label.csv"
    export_to_csv([], output_path, label=None)
    rows = list(csv.reader(output_path.open(newline="", encoding="utf-8")))
    assert len(rows[0]) == 30


def test_export_csv_column_count_with_label(tmp_path):
    output_path = tmp_path / "features_with_label.csv"
    export_to_csv([], output_path, label=1)
    rows = list(csv.reader(output_path.open(newline="", encoding="utf-8")))
    assert len(rows[0]) == 31
    assert rows[0][-1] == "label"


def test_pipeline_nonexistent_db_returns_empty(tmp_path):
    db_path = tmp_path / "does_not_exist.db"
    pipeline = FeatureExtractionPipeline(db_path)
    result = pipeline.run()
    assert result == []


# --- Time-window scoping (--since / --until) ---


def test_time_filter_since_only(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _seed_three_timed_windows(conn)
    result = _run_pipeline_with_memory_db(
        conn,
        monkeypatch,
        time_from="2026-07-14 10:00:00.000000",
    )
    assert len(result) == 2


def test_time_filter_until_only(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _seed_three_timed_windows(conn)
    result = _run_pipeline_with_memory_db(
        conn,
        monkeypatch,
        time_to="2026-07-14 10:00:00.000000",
    )
    assert len(result) == 2


def test_time_filter_both_since_and_until(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _seed_three_timed_windows(conn)
    result = _run_pipeline_with_memory_db(
        conn,
        monkeypatch,
        time_from="2026-07-14 10:00:00.000000",
        time_to="2026-07-14 10:00:00.000000",
    )
    assert len(result) == 1


def test_time_filter_neither_preserves_all_time_behavior(monkeypatch):
    # Create both connections before any pipeline.run (which monkeypatches connect
    # and closes the mapped connection in finally).
    conn = sqlite3.connect(":memory:")
    conn2 = sqlite3.connect(":memory:")
    create_test_db(conn)
    create_test_db(conn2)
    _seed_three_timed_windows(conn)
    _seed_three_timed_windows(conn2)

    unscoped = _run_pipeline_with_memory_db(conn, monkeypatch)
    scoped_none = _run_pipeline_with_memory_db(
        conn2,
        monkeypatch,
        time_from=None,
        time_to=None,
    )
    assert len(unscoped) == 3
    assert len(scoped_none) == 3
    assert len(unscoped) == len(scoped_none)


def test_time_filter_inclusive_boundaries_include_exact_since_and_until(monkeypatch):
    conn = sqlite3.connect(":memory:")
    create_test_db(conn)
    _insert_event(
        conn, 1, "2026-07-14 09:59:59.999999", 100, r"C:\Windows\System32\before.exe"
    )
    _insert_event(
        conn, 1, "2026-07-14 10:00:00.000000", 200, r"C:\Windows\System32\at_since.exe"
    )
    _insert_event(
        conn, 1, "2026-07-14 11:00:00.000000", 300, r"C:\Windows\System32\at_until.exe"
    )
    _insert_event(
        conn, 1, "2026-07-14 11:00:00.000001", 400, r"C:\Windows\System32\after.exe"
    )
    result = _run_pipeline_with_memory_db(
        conn,
        monkeypatch,
        time_from="2026-07-14 10:00:00.000000",
        time_to="2026-07-14 11:00:00.000000",
    )
    assert len(result) == 2


def test_whole_second_until_includes_same_second_excludes_next_second(monkeypatch):
    """Prove --until without fractional seconds pads to .999999.

    An event later in the same second (nonzero microseconds) must be included;
    an event in the very next second must be excluded.
    """
    # Pre-create both DBs before monkeypatched connect/close cycle.
    conn = sqlite3.connect(":memory:")
    conn2 = sqlite3.connect(":memory:")
    create_test_db(conn)
    create_test_db(conn2)
    for c in (conn, conn2):
        _insert_event(
            c,
            1,
            "2026-07-14 10:00:00.500000",
            200,
            r"C:\Windows\System32\same_second.exe",
        )
        _insert_event(
            c,
            1,
            "2026-07-14 10:00:01.000000",
            300,
            r"C:\Windows\System32\next_second.exe",
        )

    # CLI-equivalent: whole-second --until (no fractional component).
    assert parse_time_bound("2026-07-14 10:00:00", bound_name="--until") == (
        "2026-07-14 10:00:00.999999"
    )
    # Explicit fractional --until must NOT pad (contrast / asymmetry check).
    assert parse_time_bound("2026-07-14 10:00:00.500000", bound_name="--until") == (
        "2026-07-14 10:00:00.500000"
    )

    time_to = parse_time_bound("2026-07-14 10:00:00", bound_name="--until")
    result = _run_pipeline_with_memory_db(conn, monkeypatch, time_to=time_to)
    assert len(result) == 1

    # Control: bare second string (no padding) excludes .500000 under lexicographic
    # TEXT compare — the behavior padding exists to prevent.
    bare = _run_pipeline_with_memory_db(
        conn2,
        monkeypatch,
        time_to="2026-07-14 10:00:00",
    )
    assert len(bare) == 0


def test_cli_malformed_since_exits_2_before_pipeline_runs(tmp_path):
    output_path = tmp_path / "should_not_be_written.csv"
    db_path = tmp_path / "unused.db"
    # Create a usable DB so a successful run would have something to read —
    # proving exit-2 happens before any extraction/query path that exports.
    conn = sqlite3.connect(db_path)
    create_test_db(conn)
    _insert_event(
        conn, 1, "2026-07-14 10:00:00.000000", 1234, r"C:\Windows\System32\cmd.exe"
    )
    conn.close()

    proc = subprocess.run(
        [
            str(PYTHON_EXE),
            str(REPO_ROOT / "scripts" / "run_feature_extraction.py"),
            "--since",
            "not-a-date",
            "--db",
            str(db_path),
            "--output",
            str(output_path),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "[ERROR]" in proc.stderr
    assert "Invalid --since" in proc.stderr
    assert "Extracted" not in proc.stdout
    assert not output_path.exists()


def test_cli_malformed_until_exits_2(tmp_path):
    output_path = tmp_path / "should_not_be_written.csv"
    proc = subprocess.run(
        [
            str(PYTHON_EXE),
            str(REPO_ROOT / "scripts" / "run_feature_extraction.py"),
            "--until",
            "bad-timestamp",
            "--output",
            str(output_path),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "[ERROR]" in proc.stderr
    assert "Invalid --until" in proc.stderr
    assert not output_path.exists()
