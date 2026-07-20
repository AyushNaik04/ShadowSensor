"""Rule evaluation engine: loads YAML rules and evaluates them against SysmonEvents."""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rules.loader import load_rules_from_directory
from rules.schema import FIELD_REFERENCE_OPERATORS, MULTI_VALUE_OPERATORS, Condition, Rule, RuleHit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Operator functions — all operate on pre-lowercased strings
# ---------------------------------------------------------------------------


def _op_equals(field_val: str, value: str) -> bool:
    """Return True if field_val exactly equals value (case-insensitive)."""
    return field_val == value.lower()


def _op_not_equals(field_val: str, value: str) -> bool:
    """Return True if field_val does not equal value (case-insensitive)."""
    return field_val != value.lower()


def _op_contains(field_val: str, value: str) -> bool:
    """Return True if field_val contains value as a substring (case-insensitive)."""
    return value.lower() in field_val


def _op_not_contains(field_val: str, value: str) -> bool:
    """Return True if field_val does not contain value (case-insensitive)."""
    return value.lower() not in field_val


def _op_contains_any(field_val: str, values: tuple[str, ...]) -> bool:
    """Return True if field_val contains any of the provided substrings."""
    return any(v.lower() in field_val for v in values)


def _op_not_contains_any(field_val: str, values: tuple[str, ...]) -> bool:
    """Return True if field_val contains none of the provided substrings."""
    return not any(v.lower() in field_val for v in values)


def _op_ends_with_any(field_val: str, values: tuple[str, ...]) -> bool:
    """Return True if field_val ends with any of the provided suffixes."""
    return any(field_val.endswith(v.lower()) for v in values)


def _op_not_ends_with_any(field_val: str, values: tuple[str, ...]) -> bool:
    """Return True if field_val ends with none of the provided suffixes."""
    return not any(field_val.endswith(v.lower()) for v in values)


def _op_starts_with(field_val: str, value: str) -> bool:
    """Return True if field_val starts with value (case-insensitive)."""
    return field_val.startswith(value.lower())


def _op_ends_with(field_val: str, value: str) -> bool:
    """Return True if field_val ends with value (case-insensitive)."""
    return field_val.endswith(value.lower())


def _op_not_ends_with(field_val: str, value: str) -> bool:
    """Return True if field_val does not end with value (case-insensitive)."""
    return not field_val.endswith(value.lower())


def _op_regex(field_val: str, pattern: str) -> bool:
    """Return True if the regex pattern matches anywhere in field_val."""
    return bool(re.search(pattern, field_val, re.IGNORECASE))


def _basename(path_str: str) -> str:
    """Return the lowercased filename component of a Windows or POSIX path."""
    return os.path.basename(path_str.replace("\\", "/")).lower()


def _op_same_basename(field_val: str, ref_val: str) -> bool:
    """Return True if the two paths share the same filename (case-insensitive).

    Used to identify same-image-name process pairs (e.g. msedge.exe opening
    another msedge.exe) which are overwhelmingly benign multi-process-app
    behaviour rather than cross-process injection.
    """
    return _basename(field_val) == _basename(ref_val)


def _op_not_same_basename(field_val: str, ref_val: str) -> bool:
    """Return True if the two paths have different filenames (case-insensitive).

    Primary filter for OpenProcess / CreateRemoteThread rules: same-image-name
    calls are benign; different-image-name calls are the suspicious signal.
    """
    return _basename(field_val) != _basename(ref_val)


# Dispatch map — keyed by operator string, no if/elif chains in the engine.
# Field-reference operators (same_basename, not_same_basename) are handled
# separately in _evaluate_condition and are not in this map.
_OPERATOR_MAP: dict[str, Callable] = {
    "equals": _op_equals,
    "not_equals": _op_not_equals,
    "contains": _op_contains,
    "not_contains": _op_not_contains,
    "contains_any": _op_contains_any,
    "not_contains_any": _op_not_contains_any,
    "ends_with_any": _op_ends_with_any,
    "not_ends_with_any": _op_not_ends_with_any,
    "starts_with": _op_starts_with,
    "ends_with": _op_ends_with,
    "not_ends_with": _op_not_ends_with,
    "regex": _op_regex,
}


class RuleEngine:
    """Loads behavioral detection rules from YAML and evaluates them against
    normalized Sysmon events.

    Usage:
        engine = RuleEngine(rules_dir=Path("rules"))
        engine.load()
        hits = engine.evaluate(event)

    Args:
        rules_dir: Path to the rules/ package directory containing definitions/.
    """

    def __init__(self, rules_dir: Path) -> None:
        self._rules_dir = rules_dir
        self._rules: list[Rule] = []
        self._rules_by_event_id: dict[int, list[Rule]] = {}

    def load(self) -> None:
        """Load all rules from rules_dir/definitions/ and build the event-ID index.

        Logs number of rules loaded per event ID at INFO level.

        Raises:
            ValueError: From loader if any rule is invalid.
        """
        self._rules = load_rules_from_directory(self._rules_dir)
        self._rules_by_event_id = {}

        for rule in self._rules:
            for eid in rule.event_ids:
                self._rules_by_event_id.setdefault(eid, []).append(rule)

        for eid, rule_list in self._rules_by_event_id.items():
            logger.info("Event ID %d: %d rule(s) loaded", eid, len(rule_list))

    def evaluate(self, event: Any) -> list[RuleHit]:
        """Evaluate all rules applicable to this event's event_id.

        Args:
            event: A typed SysmonEvent dataclass from the normalizer.

        Returns:
            List of RuleHit objects for every rule that matched.
            Empty list if no rules matched.
        """
        event_id = getattr(event, "event_id", None)
        if event_id is None:
            return []

        applicable_rules = self._rules_by_event_id.get(event_id, [])
        hits: list[RuleHit] = []

        for rule in applicable_rules:
            hit = self._evaluate_rule(event, rule)
            if hit is not None:
                hits.append(hit)

        return hits

    def _evaluate_rule(self, event: Any, rule: Rule) -> RuleHit | None:
        """Evaluate a single rule against a single event.

        Args:
            event: A normalized SysmonEvent dataclass.
            rule: The Rule to evaluate.

        Returns:
            A RuleHit if the rule matched, None otherwise.
        """
        results = [self._evaluate_condition(event, cond) for cond in rule.conditions]

        if rule.logic == "AND":
            matched = all(results)
        else:
            matched = any(results)

        if not matched:
            return None

        fired_at = datetime.now(tz=UTC).isoformat()
        return RuleHit(
            rule_id=rule.id,
            rule_name=rule.name,
            mitre_technique=rule.mitre_technique,
            mitre_tactic=rule.mitre_tactic,
            severity=rule.severity,
            event_id=getattr(event, "event_id", 0),
            fired_at=fired_at,
            matched_event=event,
        )

    def _evaluate_condition(self, event: Any, condition: Condition) -> bool:
        """Evaluate a single condition against an event.

        Null / missing-field handling:
        - If condition.allow_null is True and the field is missing or None,
          the condition passes (returns True).  Use this on NOT-style exclusion
          conditions so that unresolved fields do not silently suppress a hit.
        - Otherwise a missing/None field returns False.
        - Field-reference operators additionally require the reference_field to
          be non-None; if either field is absent the condition returns False
          regardless of allow_null.

        Args:
            event: A normalized SysmonEvent dataclass.
            condition: The Condition to evaluate.

        Returns:
            True if the condition is satisfied, False otherwise.
        """
        raw_value = getattr(event, condition.field, None)
        if raw_value is None:
            return condition.allow_null

        try:
            field_val = str(raw_value).lower()
        except Exception:
            return False

        # Field-to-field comparison operators (same_basename, not_same_basename)
        if condition.operator in FIELD_REFERENCE_OPERATORS:
            if not condition.reference_field:
                logger.error(
                    "Operator %r requires reference_field; returning False",
                    condition.operator,
                )
                return False
            ref_raw = getattr(event, condition.reference_field, None)
            if ref_raw is None:
                return False
            try:
                ref_val = str(ref_raw).lower()
            except Exception:
                return False
            if condition.operator == "same_basename":
                return _op_same_basename(field_val, ref_val)
            else:  # not_same_basename
                return _op_not_same_basename(field_val, ref_val)

        op_fn = _OPERATOR_MAP.get(condition.operator)
        if op_fn is None:
            logger.error("Unknown operator %r in condition; returning False", condition.operator)
            return False

        if condition.operator in MULTI_VALUE_OPERATORS:
            return op_fn(field_val, condition.values)
        else:
            return op_fn(field_val, condition.value or "")

    @property
    def rule_count(self) -> int:
        """Total number of loaded rules."""
        return len(self._rules)

    @property
    def rules(self) -> list[Rule]:
        """All loaded rules as a read-only copy."""
        return list(self._rules)
