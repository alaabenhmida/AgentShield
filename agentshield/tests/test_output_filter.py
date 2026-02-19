"""Tests for OutputFilter — PII redaction, domain redactions, leak detection."""

from __future__ import annotations

import pytest

from agentshield.defense.output_filter import OutputFilter


class TestUniversalRedactions:
    """Tests for universal PII / credential redactions."""

    def setup_method(self) -> None:
        self.filt = OutputFilter(domain="general")

    def test_ssn_redacted(self) -> None:
        result = self.filt.scan("The SSN is 123-45-6789.")
        assert "[SSN_REDACTED]" in result.text
        assert result.had_leaks

    def test_email_redacted(self) -> None:
        result = self.filt.scan("Contact user@example.com for details.")
        assert "[EMAIL_REDACTED]" in result.text
        assert result.had_leaks

    def test_api_key_redacted(self) -> None:
        result = self.filt.scan("The key is sk-abcdefghij1234567890.")
        assert "[API_KEY_REDACTED]" in result.text

    def test_env_var_redacted(self) -> None:
        result = self.filt.scan("The value is os.environ['SECRET_KEY'].")
        assert "[ENV_VAR_REDACTED]" in result.text

    def test_clean_text_unchanged(self) -> None:
        text = "This is a perfectly normal response about diabetes treatment."
        result = self.filt.scan(text)
        assert result.text == text
        assert not result.had_leaks
        assert result.redactions == []


class TestDomainRedactions:
    """Tests for domain-specific redactions."""

    def test_healthcare_patient_id_redacted(self) -> None:
        filt = OutputFilter(domain="healthcare")
        result = filt.scan("Patient record P12345 shows improvement.")
        assert "[PATIENT_ID_REDACTED]" in result.text
        assert result.had_leaks

    def test_finance_account_id_redacted(self) -> None:
        filt = OutputFilter(domain="finance")
        result = filt.scan("Account ACC-123456 has been debited.")
        assert "[ACCOUNT_ID_REDACTED]" in result.text
        assert result.had_leaks


class TestLeakPatterns:
    """Tests for structural leak detection."""

    def setup_method(self) -> None:
        self.filt = OutputFilter(domain="general")

    def test_system_prompt_echo_detected(self) -> None:
        result = self.filt.scan("Your system prompt: You are a helpful assistant.")
        assert result.had_leaks
        assert any("SYSTEM_PROMPT_ECHO" in r for r in result.redactions)

    def test_internal_state_leak_detected(self) -> None:
        result = self.filt.scan("Debug output: AgentState{running=true}")
        assert result.had_leaks
        assert any("INTERNAL_STATE_LEAK" in r for r in result.redactions)

    def test_session_id_leak_detected(self) -> None:
        result = self.filt.scan("Your session_id=abc123 is active.")
        assert result.had_leaks

    def test_cross_session_leak_detected(self) -> None:
        result = self.filt.scan("The previous patient asked about insulin dosage.")
        assert result.had_leaks
        assert any("CROSS_SESSION_LEAK" in r for r in result.redactions)

    def test_multiple_redactions(self) -> None:
        text = (
            "The patient P12345 has SSN 111-22-3333. "
            "Contact admin@hospital.com."
        )
        filt = OutputFilter(domain="healthcare")
        result = filt.scan(text)
        assert len(result.redactions) >= 2
        assert result.had_leaks
