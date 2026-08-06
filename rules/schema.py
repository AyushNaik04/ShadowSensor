"""Dataclass schemas for rules, conditions, and rule match results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Condition:
    """A single condition within a rule.

    Attributes:
        field: SysmonEvent attribute name to evaluate.
        operator: One of the valid operator strings (equals, contains, etc.).
        value: Single comparison value used by all operators except contains_any /
            not_contains_any / same_basename / not_same_basename.
        values: Multi-value tuple used by contains_any and not_contains_any.
        reference_field: For field-to-field operators (same_basename,
            not_same_basename): the name of the second event field to compare
            against.  Mutually exclusive with value/values.
        allow_null: When True, a missing (None) field value causes this condition
            to pass rather than fail.  Use on NOT-style exclusion conditions so
            that unknown / unresolved fields (e.g. destination_hostname) do not
            silently suppress a rule hit.
    """

    field: str
    operator: str
    value: str | None = None
    values: tuple[str, ...] = field(default_factory=tuple)
    reference_field: str | None = None
    allow_null: bool = False


@dataclass(frozen=True)
class Rule:
    """A single behavioral detection rule loaded from YAML.

    Attributes:
        id: Unique rule identifier (e.g. PS_ENCODED_CMD_001).
        name: Short human-readable rule name.
        description: What technique or behavior this rule detects.
        mitre_technique: ATT&CK technique ID (e.g. T1059.001).
        mitre_tactic: ATT&CK tactic name (e.g. Execution).
        severity: Alert severity — one of Low, Medium, High, Critical.
        event_ids: Sysmon event IDs this rule applies to.
        logic: How conditions are combined — AND or OR.
        conditions: Ordered tuple of Condition objects to evaluate.
    """

    id: str
    name: str
    description: str
    mitre_technique: str
    mitre_tactic: str
    severity: str
    event_ids: tuple[int, ...]
    logic: str
    conditions: tuple[Condition, ...]


@dataclass(frozen=True)
class RuleHit:
    """Record of a rule matching a specific Sysmon event.

    Note: suspected_families is always an empty tuple in Phases 2-7.
    It is populated by static lookup in Phase 8A (alert correlation engine).
    Do not populate it here.

    Attributes:
        rule_id: ID of the rule that fired.
        rule_name: Human-readable name of the rule.
        mitre_technique: ATT&CK technique ID from the rule.
        mitre_tactic: ATT&CK tactic name from the rule.
        severity: Severity tier from the rule.
        event_id: Sysmon event ID of the matched event.
        fired_at: ISO timestamp string (datetime.utcnow().isoformat()).
        matched_event: The SysmonEvent dataclass that triggered this hit.
        suspected_families: Reference-only metadata; populated in Phase 8A.
    """

    rule_id: str
    rule_name: str
    mitre_technique: str
    mitre_tactic: str
    severity: str
    event_id: int
    fired_at: str
    matched_event: Any
    suspected_families: tuple[str, ...] = field(default_factory=tuple)


# Valid enum-like constants — used for validation, not hardcoded strings
VALID_SEVERITIES: frozenset[str] = frozenset({"Low", "Medium", "High", "Critical"})
VALID_LOGIC: frozenset[str] = frozenset({"AND", "OR"})
VALID_OPERATORS: frozenset[str] = frozenset(
    {
        # Literal-comparison operators (field vs. value string)
        "equals",
        "not_equals",
        "contains",
        "not_contains",
        "contains_any",
        "not_contains_any",     # Phase 2B: multi-value NOT for exclusion lists
        "bits_any_set",         # Category A: bitwise access-mask match (all mask bits present)
        "ends_with_any",        # Phase 2B: multi-value suffix match
        "not_ends_with_any",    # Phase 2B: multi-value suffix exclusion
        "starts_with",
        "ends_with",
        "not_ends_with",        # Phase 2B: complement of ends_with
        "regex",
        # Field-to-field operators (field vs. reference_field on the same event)
        "same_basename",        # Phase 2B: os.path.basename(field) == basename(reference_field)
        "not_same_basename",    # Phase 2B: basename differs — primary same-image-name filter
    }
)

# Operators that require a reference_field instead of value/values
FIELD_REFERENCE_OPERATORS: frozenset[str] = frozenset(
    {"same_basename", "not_same_basename"}
)

# Operators that use the values tuple (list-style)
MULTI_VALUE_OPERATORS: frozenset[str] = frozenset(
    {"contains_any", "not_contains_any", "bits_any_set", "ends_with_any", "not_ends_with_any"}
)
