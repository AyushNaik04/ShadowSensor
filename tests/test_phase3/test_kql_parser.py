"""Unit tests for the Phase 3 KQL parser."""

from __future__ import annotations

import pytest

from dashboard.kql.parser import KQLParseError, KQLParser


@pytest.fixture()
def parser() -> KQLParser:
    return KQLParser()


def test_parse_simple_field_value_returns_tree(parser: KQLParser) -> None:
    tree = parser.parse("severity:High")
    assert tree is not None


def test_parse_and_expression_contains_and_node(parser: KQLParser) -> None:
    tree = parser.parse("severity:High AND status:open")
    assert tree is not None
    assert "and_node" in tree.pretty()


def test_parse_or_with_wildcards(parser: KQLParser) -> None:
    tree = parser.parse("rule_name:powershell* OR rule_name:mshta*")
    assert tree is not None


def test_parse_range_value_contains_range_val(parser: KQLParser) -> None:
    tree = parser.parse("timestamp:[2026-06-01 TO 2026-06-24]")
    assert tree is not None
    assert "range_val" in tree.pretty()


def test_parse_not_expression_contains_not_node(parser: KQLParser) -> None:
    tree = parser.parse("NOT severity:Low")
    assert tree is not None
    assert "not_node" in tree.pretty()


def test_parse_parenthesized_expression(parser: KQLParser) -> None:
    tree = parser.parse("severity:High AND (status:open OR status:acknowledged)")
    assert tree is not None


def test_parse_leading_wildcard(parser: KQLParser) -> None:
    tree = parser.parse("rule_name:*encoded*")
    assert tree is not None


def test_parse_empty_string_returns_none(parser: KQLParser) -> None:
    assert parser.parse("") is None


def test_parse_whitespace_returns_none(parser: KQLParser) -> None:
    assert parser.parse("   ") is None


def test_parse_missing_value_raises(parser: KQLParser) -> None:
    with pytest.raises(KQLParseError):
        parser.parse("severity:")


def test_parse_missing_field_raises(parser: KQLParser) -> None:
    with pytest.raises(KQLParseError):
        parser.parse(":value")


def test_parse_incomplete_expression_raises(parser: KQLParser) -> None:
    with pytest.raises(KQLParseError):
        parser.parse("severity:High AND")
