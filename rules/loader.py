"""YAML rule file loader and validator for the ShadowSensor rule engine."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from rules.schema import (
    FIELD_REFERENCE_OPERATORS,
    MULTI_VALUE_OPERATORS,
    VALID_LOGIC,
    VALID_OPERATORS,
    VALID_SEVERITIES,
    Condition,
    Rule,
)

logger = logging.getLogger(__name__)


def load_rules_from_directory(rules_dir: Path) -> list[Rule]:
    """Load and validate all YAML rule files from rules_dir/definitions/.

    Scans for *.yaml files, loads each, validates schema, and returns a sorted
    list of Rule objects. Fails fast if any rule is invalid.

    Args:
        rules_dir: Path to the rules/ package directory.

    Returns:
        List of validated Rule objects sorted by rule id for deterministic ordering.

    Raises:
        ValueError: If any rule fails schema validation.
    """
    definitions_dir = rules_dir / "definitions"
    yaml_files = sorted(definitions_dir.glob("*.yaml"))

    all_rules: list[Rule] = []
    for path in yaml_files:
        file_rules = load_rule_file(path)
        all_rules.extend(file_rules)

    all_rules.sort(key=lambda r: r.id)
    logger.info("Loaded %d rules from %s", len(all_rules), definitions_dir)
    return all_rules


def load_rule_file(path: Path) -> list[Rule]:
    """Load all rules from a single YAML file.

    A single YAML file may contain multiple rules as a top-level list.

    Args:
        path: Path to the .yaml file.

    Returns:
        List of Rule objects parsed from the file.

    Raises:
        ValueError: If the YAML is malformed or any rule fails schema validation.
    """
    try:
        with path.open(encoding="utf-8") as fh:
            raw_list = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ValueError(f"Malformed YAML in {path}: {exc}") from exc

    if not isinstance(raw_list, list):
        raise ValueError(
            f"Rule file {path} must contain a top-level YAML list, got {type(raw_list).__name__}"
        )

    rules: list[Rule] = []
    for raw in raw_list:
        if not isinstance(raw, dict):
            raise ValueError(f"Each rule entry must be a dict in {path}, got {type(raw).__name__}")
        rules.append(validate_rule(raw))

    logger.debug("Loaded %d rule(s) from %s", len(rules), path)
    return rules


def validate_rule(raw: dict) -> Rule:
    """Validate a raw dict (from YAML) against the rule schema and return a Rule.

    Args:
        raw: Dictionary parsed from a YAML rule definition.

    Returns:
        A validated, frozen Rule dataclass instance.

    Raises:
        ValueError: With a descriptive message identifying which field failed and why.
    """
    required_keys = {
        "id",
        "name",
        "description",
        "mitre_technique",
        "mitre_tactic",
        "severity",
        "event_ids",
        "logic",
        "conditions",
    }
    missing = required_keys - raw.keys()
    if missing:
        raise ValueError(f"Rule is missing required keys: {sorted(missing)}")

    rule_id = raw["id"]

    severity = raw["severity"]
    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Rule {rule_id!r}: invalid severity {severity!r}. "
            f"Must be one of {sorted(VALID_SEVERITIES)}."
        )

    logic = raw["logic"]
    if logic not in VALID_LOGIC:
        raise ValueError(f"Rule {rule_id!r}: invalid logic {logic!r}. Must be AND or OR.")

    event_ids_raw = raw["event_ids"]
    if not isinstance(event_ids_raw, list) or len(event_ids_raw) == 0:
        raise ValueError(f"Rule {rule_id!r}: event_ids must be a non-empty list of ints.")
    for eid in event_ids_raw:
        if not isinstance(eid, int):
            raise ValueError(
                f"Rule {rule_id!r}: event_ids entries must be ints, got {type(eid).__name__}."
            )

    conditions_raw = raw["conditions"]
    if not isinstance(conditions_raw, list) or len(conditions_raw) == 0:
        raise ValueError(f"Rule {rule_id!r}: conditions must be a non-empty list.")

    conditions = tuple(_build_condition(c) for c in conditions_raw)

    return Rule(
        id=str(raw["id"]),
        name=str(raw["name"]),
        description=str(raw["description"]),
        mitre_technique=str(raw["mitre_technique"]),
        mitre_tactic=str(raw["mitre_tactic"]),
        severity=severity,
        event_ids=tuple(int(e) for e in event_ids_raw),
        logic=logic,
        conditions=conditions,
    )


def _build_condition(raw: dict) -> Condition:
    """Build a Condition from a raw dict.

    Supported YAML keys:
        field       — required; SysmonEvent attribute name to test.
        operator    — required; one of VALID_OPERATORS.
        value       — required for single-value operators.
        values      — required for multi-value operators (contains_any,
                      not_contains_any, ends_with_any, not_ends_with_any).
        reference_field — required for field-to-field operators
                          (same_basename, not_same_basename).
        allow_null  — optional bool (default False); when True a missing /
                      None field value causes this condition to pass rather
                      than fail.  Useful on NOT-style exclusion conditions.

    Args:
        raw: Dictionary parsed from a YAML condition entry.

    Returns:
        A validated, frozen Condition dataclass instance.

    Raises:
        ValueError: If any required field is missing or invalid.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"Each condition must be a dict, got {type(raw).__name__}.")

    field_name = raw.get("field")
    if not field_name or not isinstance(field_name, str):
        raise ValueError("Condition is missing a non-empty 'field' string.")

    operator = raw.get("operator")
    if not operator or operator not in VALID_OPERATORS:
        raise ValueError(
            f"Condition field={field_name!r}: invalid operator {operator!r}. "
            f"Must be one of {sorted(VALID_OPERATORS)}."
        )

    allow_null = bool(raw.get("allow_null", False))

    # Multi-value operators: contains_any, not_contains_any, ends_with_any,
    # not_ends_with_any
    if operator in MULTI_VALUE_OPERATORS:
        values_raw = raw.get("values")
        if not values_raw or not isinstance(values_raw, list) or len(values_raw) == 0:
            raise ValueError(
                f"Condition field={field_name!r} operator={operator!r} requires a "
                f"non-empty 'values' list."
            )
        return Condition(
            field=field_name,
            operator=operator,
            values=tuple(str(v) for v in values_raw),
            allow_null=allow_null,
        )

    # Field-to-field operators: same_basename, not_same_basename
    if operator in FIELD_REFERENCE_OPERATORS:
        ref_field = raw.get("reference_field")
        if not ref_field or not isinstance(ref_field, str):
            raise ValueError(
                f"Condition field={field_name!r} operator={operator!r} requires a "
                f"non-empty 'reference_field' string."
            )
        return Condition(
            field=field_name,
            operator=operator,
            reference_field=ref_field,
            allow_null=allow_null,
        )

    # Single-value operators: all others
    value = raw.get("value")
    if value is None or not isinstance(value, str) or value == "":
        raise ValueError(
            f"Condition field={field_name!r} operator={operator!r} requires a "
            f"non-empty 'value' string."
        )
    return Condition(field=field_name, operator=operator, value=value, allow_null=allow_null)
