"""E2 Subphase 1 tests: _op_not_contains_any None/empty guard."""

from __future__ import annotations

from pathlib import Path

import pytest
from normalizer.models import OpenProcessEvent
from rules.engine import RuleEngine, _op_not_contains_any
from rules.schema import Condition


def _make_open_process_event(**kwargs) -> OpenProcessEvent:
    """Create an OpenProcessEvent with sensible defaults for integration tests."""
    defaults: dict = {
        "event_id": 10,
        "utc_time": "2026-06-22 10:00:00.000",
        "computer": "TEST-HOST",
        "source_process_id": 1234,
        "source_image": "C:\\Users\\test\\malware.exe",
        "target_process_id": 500,
        "target_image": "C:\\Windows\\System32\\lsass.exe",
        "granted_access": "0x1410",
        "call_trace": None,
    }
    defaults.update(kwargs)
    return OpenProcessEvent(**defaults)


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    """Shared RuleEngine instance loaded once per test module."""
    eng = RuleEngine(Path("rules"))
    eng.load()
    return eng


def test_not_contains_any_none_field_returns_true():
    assert _op_not_contains_any(None, ("forbidden.dll",)) is True


def test_not_contains_any_empty_string_returns_true(engine: RuleEngine):
    event = _make_open_process_event(call_trace="")
    condition = Condition(
        field="call_trace",
        operator="not_contains_any",
        values=("forbidden.dll",),
    )
    assert engine._evaluate_condition(event, condition) is True


def test_not_contains_any_non_matching_string_returns_true(engine: RuleEngine):
    event = _make_open_process_event(
        call_trace="ntdll.dll+0x9b6f0|KERNELBASE.dll+0x12345|UNKNOWN",
    )
    condition = Condition(
        field="call_trace",
        operator="not_contains_any",
        values=("System.Management.Automation.ni.dll",),
    )
    assert engine._evaluate_condition(event, condition) is True


def test_not_contains_any_matching_string_returns_false(engine: RuleEngine):
    event = _make_open_process_event(
        call_trace="ntdll.dll+0x9b6f0|System.Management.Automation.ni.dll+0x1234|UNKNOWN",
    )
    condition = Condition(
        field="call_trace",
        operator="not_contains_any",
        values=("System.Management.Automation.ni.dll",),
    )
    assert engine._evaluate_condition(event, condition) is False
