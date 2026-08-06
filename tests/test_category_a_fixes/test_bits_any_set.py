"""Category A Subphase 1 tests: bits_any_set operator and granted_access rules."""

from __future__ import annotations

from pathlib import Path

import pytest
from normalizer.models import OpenProcessEvent
from rules.engine import RuleEngine, _OPERATOR_MAP, _op_bits_any_set
from rules.schema import MULTI_VALUE_OPERATORS, VALID_OPERATORS


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


# ---------------------------------------------------------------------------
# Operator unit tests (_op_bits_any_set)
# ---------------------------------------------------------------------------


def test_unpadded_field_matches_padded_mask():
    """A2: unpadded vs zero-padded, same numeric value → True."""
    assert _op_bits_any_set("0x40", ("0x0040",)) is True


def test_padded_field_matches_unpadded_mask():
    """Confirms symmetry of padding."""
    assert _op_bits_any_set("0x0040", ("0x40",)) is True


def test_overgranted_mask_contains_required_bits_a3_case1():
    """A3 case 1: over-granted mask contains required bits → True."""
    assert _op_bits_any_set("0x1f3fff", ("0x1f0fff",)) is True


def test_overgranted_mask_contains_required_bits_a3_case2():
    """A3 case 2: over-granted mask contains required bits → True."""
    assert _op_bits_any_set("0x1038", ("0x0038",)) is True


def test_non_matching_bits_return_false():
    """Non-matching bits correctly return False."""
    assert _op_bits_any_set("0x0010", ("0x0020",)) is False


def test_empty_field_val_returns_false():
    """Empty field_val returns False, not exception."""
    assert _op_bits_any_set("", ("0x0040",)) is False


def test_none_field_val_returns_false():
    """None field_val returns False, not exception."""
    assert _op_bits_any_set(None, ("0x0040",)) is False  # type: ignore[arg-type]


def test_invalid_hex_field_val_returns_false():
    """Invalid hex field_val returns False, not exception."""
    assert _op_bits_any_set("not_a_hex", ("0x0040",)) is False


def test_invalid_hex_in_values_skipped():
    """Invalid hex in values is skipped; returns False when no valid match."""
    assert _op_bits_any_set("0x0040", ("not_a_hex",)) is False


def test_multi_value_matches_first_entry():
    """Multi-value: matches first entry."""
    assert _op_bits_any_set("0x1fffff", ("0x1f0fff", "0x1410")) is True


def test_multi_value_matches_second_entry():
    """Multi-value: matches second entry."""
    assert _op_bits_any_set("0x1410", ("0x1f0fff", "0x1410")) is True


# ---------------------------------------------------------------------------
# Schema registration tests
# ---------------------------------------------------------------------------


def test_bits_any_set_in_valid_operators():
    """bits_any_set is present in VALID_OPERATORS."""
    assert "bits_any_set" in VALID_OPERATORS


def test_bits_any_set_in_operator_map():
    """bits_any_set is present in _OPERATOR_MAP."""
    assert "bits_any_set" in _OPERATOR_MAP


def test_bits_any_set_in_multi_value_operators():
    """bits_any_set is present in MULTI_VALUE_OPERATORS."""
    assert "bits_any_set" in MULTI_VALUE_OPERATORS


# ---------------------------------------------------------------------------
# Rule integration tests
# ---------------------------------------------------------------------------


def test_token_manipulation_fires_on_unpadded_0x40(engine: RuleEngine):
    """A2 fix: unpadded 0x40 against lsass fires API_TOKEN_MANIPULATION_001."""
    event = _make_open_process_event(
        granted_access="0x40",
        source_image="C:\\Users\\test\\malware.exe",
        target_image="C:\\Windows\\System32\\lsass.exe",
    )
    hit_ids = [h.rule_id for h in engine.evaluate(event)]
    assert "API_TOKEN_MANIPULATION_001" in hit_ids


def test_suspicious_access_fires_on_overgranted_0x1f3fff(engine: RuleEngine):
    """A3 fix case 1: over-granted 0x1f3fff against lsass fires suspicious-access rule."""
    event = _make_open_process_event(
        granted_access="0x1f3fff",
        source_image="C:\\Users\\test\\malware.exe",
        target_image="C:\\Windows\\System32\\lsass.exe",
    )
    hit_ids = [h.rule_id for h in engine.evaluate(event)]
    assert "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001" in hit_ids


def test_vm_write_fires_on_overgranted_0x1038(engine: RuleEngine):
    """A3 fix case 2: over-granted 0x1038 against notepad fires VM-write rule."""
    event = _make_open_process_event(
        granted_access="0x1038",
        source_image="C:\\Users\\test\\malware.exe",
        target_image="C:\\Windows\\System32\\notepad.exe",
    )
    hit_ids = [h.rule_id for h in engine.evaluate(event)]
    assert "API_OPEN_PROCESS_VM_WRITE_001" in hit_ids


def test_suspicious_access_does_not_fire_on_vm_read_only(engine: RuleEngine):
    """Non-matching bits (VM_READ only) still correctly blocked."""
    event = _make_open_process_event(
        granted_access="0x0010",
        source_image="C:\\Users\\test\\malware.exe",
        target_image="C:\\Windows\\System32\\lsass.exe",
    )
    hit_ids = [h.rule_id for h in engine.evaluate(event)]
    assert "API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001" not in hit_ids
