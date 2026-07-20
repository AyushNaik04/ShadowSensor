"""KQL parse-tree to SQLAlchemy filter transformer."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from lark import Token, Tree
from sqlalchemy import DateTime, Float, Integer, and_, not_, or_
from sqlalchemy.sql.elements import ColumnElement

from storage.models import AlertRecord, EventRecord, RuleHitRecord

ContextType = Literal["alerts", "events", "rule_hits"]


class KQLTransformError(Exception):
    """Raised when a field is not queryable in the current context."""


class KQLTransformer:
    """Transform a KQL parse tree into a SQLAlchemy WHERE clause."""

    QUERYABLE_FIELDS: dict[str, dict[str, Any]] = {
        "alerts": {
            "rule_id": AlertRecord.rule_id,
            "rule_name": AlertRecord.rule_name,
            "severity": AlertRecord.severity,
            "mitre_technique": AlertRecord.mitre_technique,
            "mitre_tactic": AlertRecord.mitre_tactic,
            "process_image": AlertRecord.process_image,
            "process_pid": AlertRecord.process_pid,
            "command_line": AlertRecord.command_line,
            "parent_image": AlertRecord.parent_image,
            "status": AlertRecord.status,
            "timestamp": AlertRecord.timestamp,
        },
        "events": {
            "event_type_id": EventRecord.event_type_id,
            "image": EventRecord.image,
            "pid": EventRecord.pid,
            "timestamp": EventRecord.timestamp,
            "raw_json": EventRecord.raw_json,
        },
        "rule_hits": {
            "rule_id": RuleHitRecord.rule_id,
            "rule_name": RuleHitRecord.rule_name,
            "severity": RuleHitRecord.severity,
            "mitre_technique": RuleHitRecord.mitre_technique,
            "timestamp": RuleHitRecord.timestamp,
        },
    }

    def __init__(self, context: ContextType) -> None:
        self._context = context
        self._field_map = self.QUERYABLE_FIELDS.get(context)
        if self._field_map is None:
            raise KQLTransformError(f"Unsupported context '{context}'.")

    def transform(self, tree: Optional[Tree]) -> Optional[Any]:
        """Convert parse tree to SQLAlchemy WHERE clause.

        Returns None for empty/None tree.
        """
        if tree is None:
            return None
        if not isinstance(tree, Tree):
            raise KQLTransformError("Expected a parse tree.")
        return self._transform_node(tree)

    def _transform_node(self, node: Tree | Token) -> ColumnElement[bool]:
        if isinstance(node, Token):
            raise KQLTransformError("Unexpected terminal token in expression tree.")

        if node.data == "comparison":
            return self._transform_comparison(node)
        if node.data == "and_node":
            return and_(self._transform_node(node.children[0]), self._transform_node(node.children[-1]))
        if node.data == "or_node":
            return or_(self._transform_node(node.children[0]), self._transform_node(node.children[-1]))
        if node.data == "not_node":
            return not_(self._transform_node(node.children[-1]))

        if len(node.children) == 1 and isinstance(node.children[0], Tree):
            return self._transform_node(node.children[0])
        raise KQLTransformError(f"Unsupported parse node '{node.data}'.")

    def _transform_comparison(self, node: Tree) -> ColumnElement[bool]:
        field_name = str(node.children[0])
        column = self._field_map.get(field_name)
        if column is None:
            available = ", ".join(sorted(self._field_map.keys()))
            raise KQLTransformError(
                f"Field '{field_name}' not queryable in '{self._context}'. Available: {available}"
            )

        value_node = node.children[1]
        if not isinstance(value_node, Tree):
            raise KQLTransformError("Invalid value node in comparison.")

        if value_node.data == "plain":
            return self._apply_plain(column, str(value_node.children[0]))
        if value_node.data == "quoted":
            quoted = str(value_node.children[0])
            unquoted = quoted[1:-1]
            return column.ilike(f"%{unquoted}%")
        if value_node.data == "wildcard":
            wildcard = str(value_node.children[0]).replace("*", "%").replace("?", "_")
            return column.ilike(wildcard)
        if value_node.data == "range_val":
            range_children = [
                child
                for child in value_node.children
                if not (isinstance(child, Token) and child.type == "TO")
            ]
            lower_raw = self._extract_bound(range_children[0])
            upper_raw = self._extract_bound(range_children[1])
            return self._apply_range(column, lower_raw, upper_raw, field_name)

        raise KQLTransformError(f"Unsupported value type '{value_node.data}'.")

    @staticmethod
    def _extract_bound(bound_node: Tree | Token) -> Optional[str]:
        if isinstance(bound_node, Tree) and bound_node.children:
            token = bound_node.children[0]
            value = str(token)
        else:
            value = str(bound_node)
        return None if value == "*" else value

    @staticmethod
    def _is_numeric(column: Any) -> bool:
        return isinstance(column.type, (Integer, Float))

    @staticmethod
    def _is_datetime(column: Any) -> bool:
        return isinstance(column.type, DateTime)

    def _apply_plain(self, column: Any, value: str) -> ColumnElement[bool]:
        if self._is_numeric(column):
            try:
                return column == int(value)
            except ValueError as exc:
                raise KQLTransformError(f"Invalid integer value '{value}'.") from exc
        return column.ilike(f"%{value}%")

    def _apply_range(
        self,
        column: Any,
        lower_raw: Optional[str],
        upper_raw: Optional[str],
        field_name: str,
    ) -> ColumnElement[bool]:
        if self._is_numeric(column):
            lower = self._coerce_int(lower_raw, field_name)
            upper = self._coerce_int(upper_raw, field_name)
        elif self._is_datetime(column):
            lower = self._coerce_datetime(lower_raw, field_name)
            upper = self._coerce_datetime(upper_raw, field_name)
        else:
            lower = lower_raw
            upper = upper_raw

        if lower is None and upper is None:
            raise KQLTransformError("Open-ended range must include at least one bound.")
        if lower is None:
            return column <= upper
        if upper is None:
            return column >= lower
        return column.between(lower, upper)

    @staticmethod
    def _coerce_int(raw_value: Optional[str], field_name: str) -> Optional[int]:
        if raw_value is None:
            return None
        try:
            return int(raw_value)
        except ValueError as exc:
            raise KQLTransformError(f"Invalid integer range bound '{raw_value}' for '{field_name}'.") from exc

    @staticmethod
    def _coerce_datetime(raw_value: Optional[str], field_name: str) -> Optional[datetime]:
        if raw_value is None:
            return None
        candidate = raw_value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise KQLTransformError(
                f"Invalid datetime range bound '{raw_value}' for '{field_name}'. Use ISO 8601."
            ) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)
        return parsed
