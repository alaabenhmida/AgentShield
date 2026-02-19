"""Legal domain plugin — extends keywords, redactions, and provides factory."""

from __future__ import annotations

from agentshield.defense.prompt_guard import DOMAIN_KEYWORDS, PromptInjectionGuard
from agentshield.defense.output_filter import DOMAIN_REDACTIONS, OutputFilter
from agentshield.defense.rag_shield import RAGShield

# ------------------------------------------------------------------
# Extend (not replace) the legal keyword list
# ------------------------------------------------------------------

DOMAIN_KEYWORDS.setdefault("legal", []).extend([
    "deposition", "subpoena", "plaintiff", "defendant",
    "indictment", "habeas corpus", "tort", "injunction",
    "arbitration", "statute of limitations",
])

# ------------------------------------------------------------------
# Extend legal redaction patterns
# ------------------------------------------------------------------

DOMAIN_REDACTIONS.setdefault("legal", []).extend([
    (r"\b\d{4}-[A-Z]{2,3}-\d{3,6}\b", "[CASE_NUMBER_REDACTED]"),  # Case numbers e.g. 2024-CV-001
    (r"\bBAR-?\d{5,8}\b", "[BAR_NUMBER_REDACTED]"),  # Bar numbers
])

# ------------------------------------------------------------------
# Trusted legal domains for RAG source validation
# ------------------------------------------------------------------

TRUSTED_LEGAL_DOMAINS: list[str] = [
    "law.cornell.edu",
    "supremecourt.gov",
    "justia.com",
]


def create_legal_shield(
    trusted_rag_domains: list[str] | None = None,
) -> tuple[PromptInjectionGuard, RAGShield, OutputFilter]:
    """Create a pre-configured legal defence stack.

    Returns:
        A tuple of ``(PromptInjectionGuard, RAGShield, OutputFilter)`` ready to use.
    """
    domains = trusted_rag_domains if trusted_rag_domains is not None else list(TRUSTED_LEGAL_DOMAINS)
    return (
        PromptInjectionGuard(domain="legal"),
        RAGShield(trusted_domains=domains),
        OutputFilter(domain="legal"),
    )
