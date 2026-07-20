"""KQLParser: wraps the Lark grammar to parse KQL-style query strings."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from lark import Lark, Tree
from lark.exceptions import LarkError


class KQLParseError(Exception):
    """Raised when a query string cannot be parsed."""


class KQLParser:
    """Parse user-provided KQL-like query strings into a Lark parse tree."""

    _GRAMMAR_PATH = Path(__file__).parent / "grammar.lark"

    def __init__(self) -> None:
        with self._GRAMMAR_PATH.open("r", encoding="utf-8") as file_handle:
            grammar = file_handle.read()
        self._parser = Lark(grammar, parser="lalr", propagate_positions=False)

    def parse(self, query: str) -> Optional[Tree]:
        """Parse a query string into a syntax tree.

        Args:
            query: KQL-style query string from user input.

        Returns:
            Parsed tree on success, or None when input is empty/whitespace.

        Raises:
            KQLParseError: If the provided query has invalid syntax.
        """
        stripped = query.strip()
        if not stripped:
            return None
        try:
            return self._parser.parse(stripped)
        except LarkError as exc:
            raise KQLParseError(f"Invalid query syntax: {exc}") from exc
