"""Tests for the YAML rule loader and schema validator."""

from __future__ import annotations

from pathlib import Path

import pytest
from rules.loader import load_rule_file, load_rules_from_directory, validate_rule
from rules.schema import VALID_SEVERITIES, Rule


def _valid_rule_dict(**overrides) -> dict:
    """Return a minimal valid rule dict, with optional field overrides."""
    base = {
        "id": "TEST_001",
        "name": "Test Rule",
        "description": "Test.",
        "mitre_technique": "T1059.001",
        "mitre_tactic": "Execution",
        "severity": "High",
        "event_ids": [1],
        "logic": "AND",
        "conditions": [{"field": "image", "operator": "ends_with", "value": "powershell.exe"}],
    }
    base.update(overrides)
    return base


def test_validate_rule_valid_rule_returns_rule_object():
    """Valid rule dict passes validate_rule and returns a Rule with correct fields."""
    raw = _valid_rule_dict()
    rule = validate_rule(raw)
    assert isinstance(rule, Rule)
    assert rule.id == "TEST_001"
    assert rule.severity == "High"
    assert len(rule.conditions) == 1
    assert rule.conditions[0].field == "image"


def test_validate_rule_invalid_severity_raises():
    """Invalid severity value raises ValueError mentioning 'severity'."""
    raw = _valid_rule_dict(severity="Catastrophic")
    with pytest.raises(ValueError, match="severity"):
        validate_rule(raw)


def test_validate_rule_invalid_logic_raises():
    """Invalid logic value raises ValueError."""
    raw = _valid_rule_dict(logic="XOR")
    with pytest.raises(ValueError, match="logic"):
        validate_rule(raw)


def test_validate_rule_missing_required_key_raises():
    """A rule dict missing a required key raises ValueError."""
    raw = _valid_rule_dict()
    del raw["mitre_technique"]
    with pytest.raises(ValueError, match="missing required keys"):
        validate_rule(raw)


def test_validate_rule_empty_event_ids_raises():
    """An empty event_ids list raises ValueError."""
    raw = _valid_rule_dict(event_ids=[])
    with pytest.raises(ValueError, match="event_ids"):
        validate_rule(raw)


def test_validate_rule_contains_any_without_values_raises():
    """contains_any condition without a 'values' list raises ValueError mentioning 'values'."""
    raw = _valid_rule_dict(conditions=[{"field": "command_line", "operator": "contains_any"}])
    with pytest.raises(ValueError, match="values"):
        validate_rule(raw)


def test_validate_rule_missing_value_raises():
    """A non-contains_any condition without 'value' raises ValueError."""
    raw = _valid_rule_dict(conditions=[{"field": "command_line", "operator": "contains"}])
    with pytest.raises(ValueError):
        validate_rule(raw)


def test_validate_rule_invalid_operator_raises():
    """An unrecognised operator string raises ValueError."""
    raw = _valid_rule_dict(conditions=[{"field": "image", "operator": "like", "value": "ps.exe"}])
    with pytest.raises(ValueError, match="operator"):
        validate_rule(raw)


def test_validate_rule_contains_any_with_values_succeeds():
    """contains_any condition with a populated values list passes validation."""
    raw = _valid_rule_dict(
        conditions=[
            {
                "field": "command_line",
                "operator": "contains_any",
                "values": ["-enc", "-ec"],
            }
        ]
    )
    rule = validate_rule(raw)
    assert rule.conditions[0].values == ("-enc", "-ec")


def test_validate_rule_event_ids_stored_as_tuple():
    """event_ids are stored as a tuple of ints on the Rule."""
    raw = _valid_rule_dict(event_ids=[1, 3])
    rule = validate_rule(raw)
    assert rule.event_ids == (1, 3)


def test_load_rules_from_directory_returns_49_rules():
    """Loading the definitions directory returns exactly 49 rules after rule split correction."""
    rules_dir = Path("rules")
    rules = load_rules_from_directory(rules_dir)
    assert len(rules) == 49


def test_loaded_rules_have_unique_ids():
    """All loaded rules have unique IDs."""
    rules = load_rules_from_directory(Path("rules"))
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "Duplicate rule IDs detected"


def test_loaded_rules_have_valid_severities():
    """All loaded rules have severity values within the valid set."""
    rules = load_rules_from_directory(Path("rules"))
    for rule in rules:
        assert rule.severity in VALID_SEVERITIES, (
            f"Rule {rule.id} has invalid severity {rule.severity!r}"
        )


def test_loaded_rules_sorted_by_id():
    """Rules returned by load_rules_from_directory are sorted by ID."""
    rules = load_rules_from_directory(Path("rules"))
    ids = [r.id for r in rules]
    assert ids == sorted(ids), "Rules not sorted by ID"


def test_load_rule_file_powershell_returns_11_rules():
    """The powershell.yaml file contains exactly 11 rules (Phase 4A Subphase 2)."""
    path = Path("rules") / "definitions" / "powershell.yaml"
    rules = load_rule_file(path)
    assert len(rules) == 11


def test_load_rule_file_api_memory_returns_2_rules():
    """The api_memory.yaml file contains exactly 7 rules."""
    path = Path("rules") / "definitions" / "api_memory.yaml"
    rules = load_rule_file(path)
    assert len(rules) == 7


def test_load_rule_file_network_returns_1_rule():
    """The network.yaml file contains exactly 8 rules."""
    path = Path("rules") / "definitions" / "network.yaml"
    rules = load_rule_file(path)
    assert len(rules) == 8
