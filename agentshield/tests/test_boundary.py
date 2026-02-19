"""Tests for BoundaryEnforcer — wrapping, unwrapping, and system prefix."""

from __future__ import annotations

import pytest

from agentshield.defense.boundary import (
    BoundaryEnforcer,
    START_TOKEN,
    END_TOKEN,
    SECURITY_PREFIX,
)


class TestBoundaryEnforcer:
    """Tests for boundary wrapping and unwrapping."""

    def setup_method(self) -> None:
        self.enforcer = BoundaryEnforcer()

    def test_wrap_contains_tokens(self) -> None:
        wrapped = self.enforcer.wrap("Hello world")
        assert START_TOKEN in wrapped
        assert END_TOKEN in wrapped
        assert "Hello world" in wrapped

    def test_wrap_format(self) -> None:
        wrapped = self.enforcer.wrap("test input")
        expected = f"{START_TOKEN}\ntest input\n{END_TOKEN}"
        assert wrapped == expected

    def test_unwrap_extracts_content(self) -> None:
        original = "My original message"
        wrapped = self.enforcer.wrap(original)
        extracted = self.enforcer.unwrap(wrapped)
        assert extracted == original

    def test_unwrap_without_tokens_returns_original(self) -> None:
        text = "Just plain text without any tokens"
        assert self.enforcer.unwrap(text) == text

    def test_unwrap_partial_tokens_returns_original(self) -> None:
        text = f"Only start token {START_TOKEN} but no end token"
        assert self.enforcer.unwrap(text) == text

    def test_prefix_system_prepends_security_prefix(self) -> None:
        system = "You are a helpful medical assistant."
        result = self.enforcer.prefix_system(system)
        assert result.startswith(SECURITY_PREFIX)
        assert system in result

    def test_prefix_system_empty_prompt(self) -> None:
        result = self.enforcer.prefix_system()
        assert SECURITY_PREFIX in result

    def test_wrap_preserves_multiline(self) -> None:
        multiline = "Line 1\nLine 2\nLine 3"
        wrapped = self.enforcer.wrap(multiline)
        unwrapped = self.enforcer.unwrap(wrapped)
        assert unwrapped == multiline

    def test_wrap_preserves_special_characters(self) -> None:
        special = "Query with 'quotes' and \"double quotes\" and <tags>"
        wrapped = self.enforcer.wrap(special)
        unwrapped = self.enforcer.unwrap(wrapped)
        assert unwrapped == special
