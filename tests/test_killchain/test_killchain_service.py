"""Unit tests for kill chain backend service helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml

from dashboard.services.killchain_service import (
    TACTIC_DISPLAY_ORDER,
    format_relative_time,
    get_kill_chain_status,
    get_tactic_rule_detail,
    load_rule_tactic_map,
)


def _write_yaml(path: Path, payload: list[dict]) -> None:
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _mock_session_with_rows(rows: list[SimpleNamespace]) -> MagicMock:
    query = MagicMock()
    query.filter.return_value = query
    query.all.return_value = rows

    session = MagicMock()
    session.query.return_value = query
    return session


def _window() -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    return now - timedelta(hours=1), now + timedelta(hours=1)


def _sample_rule_map() -> dict:
    return {
        "RULE_EXEC_1": {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059.001",
            "technique_name": "",
            "rule_name": "PowerShell Encoded Command",
        },
        "RULE_EXEC_2": {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059.003",
            "technique_name": "",
            "rule_name": "Windows Command Shell",
        },
        "RULE_DE_1": {
            "tactic_id": "TA0005",
            "tactic_name": "Defense Evasion",
            "technique_id": "T1218.005",
            "technique_name": "",
            "rule_name": "MSHTA Execution",
        },
        "RULE_DE_2": {
            "tactic_id": "TA0005",
            "tactic_name": "Defense Evasion",
            "technique_id": "T1140",
            "technique_name": "",
            "rule_name": "Certutil Decode",
        },
    }


def test_load_rule_tactic_map_happy_path(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path / "one.yaml",
        [
            {
                "id": "RULE_1",
                "name": "Rule One",
                "mitre_technique": "T1059.001",
                "mitre_tactic": "Execution",
                "severity": "High",
            }
        ],
    )
    result = load_rule_tactic_map(str(tmp_path))
    assert "RULE_1" in result
    assert result["RULE_1"]["rule_name"] == "Rule One"
    assert result["RULE_1"]["technique_id"] == "T1059.001"
    assert result["RULE_1"]["tactic_id"] == "TA0002"


def test_load_rule_tactic_map_missing_tactic_field(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path / "one.yaml",
        [{"id": "RULE_1", "name": "Rule One", "mitre_technique": "T1059.001", "severity": "High"}],
    )
    result = load_rule_tactic_map(str(tmp_path))
    assert result["RULE_1"]["tactic_id"] == ""
    assert result["RULE_1"]["tactic_name"] == ""


def test_load_rule_tactic_map_unknown_tactic_value(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path / "one.yaml",
        [
            {
                "id": "RULE_1",
                "name": "Rule One",
                "mitre_technique": "T1059.001",
                "mitre_tactic": "Unknown Tactic",
                "severity": "High",
            }
        ],
    )
    result = load_rule_tactic_map(str(tmp_path))
    assert result["RULE_1"]["tactic_id"] == "UNKNOWN"


def test_load_rule_tactic_map_tactic_matched_by_name(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path / "one.yaml",
        [
            {
                "id": "RULE_1",
                "name": "Rule One",
                "mitre_technique": "T1059.001",
                "mitre_tactic": "execution",
                "severity": "High",
            }
        ],
    )
    result = load_rule_tactic_map(str(tmp_path))
    assert result["RULE_1"]["tactic_id"] == "TA0002"


def test_load_rule_tactic_map_tactic_matched_by_id(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path / "one.yaml",
        [
            {
                "id": "RULE_1",
                "name": "Rule One",
                "mitre_technique": "T1059.001",
                "mitre_tactic": "TA0002",
                "severity": "High",
            }
        ],
    )
    result = load_rule_tactic_map(str(tmp_path))
    assert result["RULE_1"]["tactic_id"] == "TA0002"


def test_load_rule_tactic_map_empty_directory(tmp_path: Path) -> None:
    assert load_rule_tactic_map(str(tmp_path)) == {}


def test_load_rule_tactic_map_nonexistent_directory(tmp_path: Path) -> None:
    assert load_rule_tactic_map(str(tmp_path / "missing")) == {}


def test_load_rule_tactic_map_multiple_rules(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path / "one.yaml",
        [
            {"id": "RULE_1", "name": "Rule One", "mitre_technique": "T1", "mitre_tactic": "Execution"},
            {"id": "RULE_2", "name": "Rule Two", "mitre_technique": "T2", "mitre_tactic": "Defense Evasion"},
        ],
    )
    _write_yaml(
        tmp_path / "two.yml",
        [{"id": "RULE_3", "name": "Rule Three", "mitre_technique": "T3", "mitre_tactic": "Initial Access"}],
    )
    result = load_rule_tactic_map(str(tmp_path))
    assert sorted(result.keys()) == ["RULE_1", "RULE_2", "RULE_3"]


def test_format_relative_time_none() -> None:
    assert format_relative_time(None) == "—"


def test_format_relative_time_just_now() -> None:
    assert format_relative_time(datetime.utcnow() - timedelta(seconds=30)) == "just now"


def test_format_relative_time_minutes() -> None:
    assert format_relative_time(datetime.utcnow() - timedelta(minutes=5)) == "5m ago"


def test_format_relative_time_hours() -> None:
    assert format_relative_time(datetime.utcnow() - timedelta(hours=3)) == "3h ago"


def test_format_relative_time_days() -> None:
    assert format_relative_time(datetime.utcnow() - timedelta(days=2)) == "2d ago"


def test_format_relative_time_boundary_59s() -> None:
    assert format_relative_time(datetime.utcnow() - timedelta(seconds=59)) == "just now"


def test_format_relative_time_boundary_60s() -> None:
    assert format_relative_time(datetime.utcnow() - timedelta(seconds=60)) == "1m ago"


def test_get_kill_chain_status_empty_db() -> None:
    session = _mock_session_with_rows([])
    start, end = _window()
    statuses = get_kill_chain_status(session, start, end, _sample_rule_map())
    assert len(statuses) == 12
    assert all(not s.fired for s in statuses)
    assert all(s.hit_count == 0 for s in statuses)


def test_get_kill_chain_status_one_hit() -> None:
    start, end = _window()
    row = SimpleNamespace(rule_id="RULE_EXEC_1", timestamp=start + timedelta(minutes=1))
    statuses = get_kill_chain_status(_mock_session_with_rows([row]), start, end, _sample_rule_map())
    execution = next(s for s in statuses if s.tactic_id == "TA0002")
    assert execution.fired is True
    assert execution.hit_count == 1


def test_get_kill_chain_status_multiple_hits_same_rule() -> None:
    start, end = _window()
    rows = [
        SimpleNamespace(rule_id="RULE_EXEC_1", timestamp=start + timedelta(minutes=1)),
        SimpleNamespace(rule_id="RULE_EXEC_1", timestamp=start + timedelta(minutes=2)),
        SimpleNamespace(rule_id="RULE_EXEC_1", timestamp=start + timedelta(minutes=3)),
    ]
    statuses = get_kill_chain_status(_mock_session_with_rows(rows), start, end, _sample_rule_map())
    execution = next(s for s in statuses if s.tactic_id == "TA0002")
    assert execution.hit_count == 3


def test_get_kill_chain_status_multiple_rules_same_tactic() -> None:
    start, end = _window()
    rows = [
        SimpleNamespace(rule_id="RULE_DE_1", timestamp=start + timedelta(minutes=1)),
        SimpleNamespace(rule_id="RULE_DE_2", timestamp=start + timedelta(minutes=2)),
    ]
    statuses = get_kill_chain_status(_mock_session_with_rows(rows), start, end, _sample_rule_map())
    defense = next(s for s in statuses if s.tactic_id == "TA0005")
    assert defense.hit_count == 2
    assert len(defense.fired_rules) == 2


def test_get_kill_chain_status_hit_before_window() -> None:
    start, end = _window()
    row = SimpleNamespace(rule_id="RULE_EXEC_1", timestamp=start - timedelta(seconds=1))
    statuses = get_kill_chain_status(_mock_session_with_rows([row]), start, end, _sample_rule_map())
    execution = next(s for s in statuses if s.tactic_id == "TA0002")
    assert execution.hit_count == 0


def test_get_kill_chain_status_hit_after_window() -> None:
    start, end = _window()
    row = SimpleNamespace(rule_id="RULE_EXEC_1", timestamp=end + timedelta(seconds=1))
    statuses = get_kill_chain_status(_mock_session_with_rows([row]), start, end, _sample_rule_map())
    execution = next(s for s in statuses if s.tactic_id == "TA0002")
    assert execution.hit_count == 0


def test_get_kill_chain_status_correct_order() -> None:
    statuses = get_kill_chain_status(_mock_session_with_rows([]), *_window(), _sample_rule_map())
    assert [s.tactic_id for s in statuses] == [entry["tactic_id"] for entry in TACTIC_DISPLAY_ORDER]


def test_get_kill_chain_status_total_rules_mapped() -> None:
    statuses = get_kill_chain_status(_mock_session_with_rows([]), *_window(), _sample_rule_map())
    execution = next(s for s in statuses if s.tactic_id == "TA0002")
    assert execution.total_rules_mapped == 2


def test_get_kill_chain_status_db_exception() -> None:
    session = MagicMock()
    session.query.side_effect = RuntimeError("db down")
    statuses = get_kill_chain_status(session, *_window(), _sample_rule_map())
    assert len(statuses) == 12
    assert all(not status.fired for status in statuses)


def test_get_kill_chain_status_all_rule_ids_populated() -> None:
    statuses = get_kill_chain_status(_mock_session_with_rows([]), *_window(), _sample_rule_map())
    defense = next(s for s in statuses if s.tactic_id == "TA0005")
    assert defense.all_rule_ids == ["RULE_DE_1", "RULE_DE_2"]


def test_get_tactic_rule_detail_valid_tactic_fired_rules() -> None:
    start, end = _window()
    rows = [
        SimpleNamespace(rule_id="RULE_DE_1", timestamp=start + timedelta(minutes=1)),
        SimpleNamespace(rule_id="RULE_DE_2", timestamp=start + timedelta(minutes=2)),
        SimpleNamespace(rule_id="RULE_DE_2", timestamp=start + timedelta(minutes=3)),
    ]
    details = get_tactic_rule_detail(
        _mock_session_with_rows(rows),
        "TA0005",
        start,
        end,
        _sample_rule_map(),
    )
    assert [item.rule_id for item in details] == ["RULE_DE_2", "RULE_DE_1"]
    assert len(details) == 2


def test_get_tactic_rule_detail_valid_tactic_no_hits() -> None:
    details = get_tactic_rule_detail(_mock_session_with_rows([]), "TA0005", *_window(), _sample_rule_map())
    assert details == []


def test_get_tactic_rule_detail_invalid_tactic_id() -> None:
    details = get_tactic_rule_detail(_mock_session_with_rows([]), "INVALID_TACTIC", *_window(), _sample_rule_map())
    assert details == []


def test_get_tactic_rule_detail_db_exception() -> None:
    session = MagicMock()
    session.query.side_effect = RuntimeError("db down")
    details = get_tactic_rule_detail(session, "TA0005", *_window(), _sample_rule_map())
    assert details == []
