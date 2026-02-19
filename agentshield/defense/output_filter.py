"""Output filter — redacts PII, credentials, and structural leaks from agent responses."""

from __future__ import annotations

import logging
import re

from agentshield.core.types import FilteredOutput

log = logging.getLogger("agentshield.output_filter")

# ======================================================================
# Universal PII / credential redactions  (pre-compiled)
# ======================================================================

_UNIVERSAL_REDACTION_DEFS: list[tuple[str, str]] = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN_REDACTED]"),
    (r"\b(?:\d[ -]*?){13,16}\b", "[CC_REDACTED]"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[EMAIL_REDACTED]"),
    (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[PHONE_REDACTED]"),
    (r"\b(?:sk-|gsk_|GROQ_|OPENAI_API_KEY|API_KEY)[A-Za-z0-9_-]{10,}\b", "[API_KEY_REDACTED]"),
    (r"os\.environ\[.*?\]|os\.getenv\(.*?\)", "[ENV_VAR_REDACTED]"),
]

UNIVERSAL_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p), repl) for p, repl in _UNIVERSAL_REDACTION_DEFS
]

# ======================================================================
# Domain-specific redactions  (compiled lazily per-domain)
# ======================================================================

DOMAIN_REDACTIONS: dict[str, list[tuple[str, str]]] = {
    "healthcare": [
        (r"\b(?:P|MRN-?)\d{4,}\b", "[PATIENT_ID_REDACTED]"),
        (r"\b(?:DOB|Date of Birth)\s*:?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", "[DOB_REDACTED]"),
    ],
    "finance": [
        (r"\bACC-?\d{4,}\b", "[ACCOUNT_ID_REDACTED]"),
        (r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})?\b", "[IBAN_REDACTED]"),
    ],
}

# ======================================================================
# Structural leak indicators  (pre-compiled)
# ======================================================================

_LEAK_PATTERN_DEFS: list[tuple[str, str]] = [
    (r"(?:system\s+prompt|instructions?\s+(?:are|is))\s*[:=]", "system_prompt_echo"),
    (r"AgentState\{", "internal_state_leak"),
    (r"\b(?:thread_id|session_id)\s*[:=]", "session_id_leak"),
    (r"(?:previous|other)\s+(?:user|patient|client)\s+(?:asked|said|requested)", "cross_session_leak"),
]

LEAK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p, re.IGNORECASE), lbl) for p, lbl in _LEAK_PATTERN_DEFS
]


class OutputFilter:
    """Scans and redacts sensitive content from agent responses."""

    def __init__(self, domain: str = "general") -> None:
        self._domain = domain
        # Domain patterns stay as raw strings since domains extend them at runtime
        self._domain_patterns = DOMAIN_REDACTIONS.get(domain, [])

    def scan(self, text: str) -> FilteredOutput:
        """Apply all redaction layers and return a :class:`FilteredOutput`."""
        redactions: list[str] = []
        current = text

        # 1 — Universal redactions (pre-compiled)
        for compiled, replacement in UNIVERSAL_REDACTIONS:
            current, n = compiled.subn(replacement, current)
            if n:
                redactions.append(replacement)

        # 2 — Domain-specific redactions (raw strings — compiled on-the-fly
        #     because domain plugins may extend these at import time)
        for pattern, replacement in self._domain_patterns:
            current, n = re.subn(pattern, replacement, current)
            if n:
                redactions.append(replacement)

        # 3 — Structural leak patterns (pre-compiled)
        for compiled, label in LEAK_PATTERNS:
            replacement_label = f"[{label.upper()}_REDACTED]"
            current, n = compiled.subn(replacement_label, current)
            if n:
                redactions.append(replacement_label)

        return FilteredOutput(
            text=current,
            redactions=redactions,
            had_leaks=bool(redactions),
        )
