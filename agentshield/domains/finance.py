"""Finance domain plugin — extends keywords, redactions, and provides factory."""

from __future__ import annotations

from agentshield.defense.prompt_guard import DOMAIN_KEYWORDS, PromptInjectionGuard
from agentshield.defense.output_filter import DOMAIN_REDACTIONS, OutputFilter
from agentshield.defense.rag_shield import RAGShield

# ------------------------------------------------------------------
# Extend (not replace) the finance keyword list
# ------------------------------------------------------------------

DOMAIN_KEYWORDS.setdefault("finance", []).extend([
    "wire transfer", "routing number", "swift", "iban",
    "securities", "equity", "derivatives", "hedge",
    "mutual fund", "brokerage",
])

# ------------------------------------------------------------------
# Extend finance redaction patterns
# ------------------------------------------------------------------

DOMAIN_REDACTIONS.setdefault("finance", []).extend([
    (r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b", "[SWIFT_REDACTED]"),  # SWIFT/BIC code
    (r"\b\d{9}\b", "[ROUTING_NUMBER_REDACTED]"),  # US routing number (9 digits)
])

# ------------------------------------------------------------------
# Trusted finance domains for RAG source validation
# ------------------------------------------------------------------

TRUSTED_FINANCE_DOMAINS: list[str] = [
    "sec.gov",
    "federalreserve.gov",
    "finra.org",
    "fdic.gov",
]


def create_finance_shield(
    trusted_rag_domains: list[str] | None = None,
) -> tuple[PromptInjectionGuard, RAGShield, OutputFilter]:
    """Create a pre-configured finance defence stack.

    Returns:
        A tuple of ``(PromptInjectionGuard, RAGShield, OutputFilter)`` ready to use.
    """
    domains = trusted_rag_domains if trusted_rag_domains is not None else list(TRUSTED_FINANCE_DOMAINS)
    return (
        PromptInjectionGuard(domain="finance"),
        RAGShield(trusted_domains=domains),
        OutputFilter(domain="finance"),
    )
