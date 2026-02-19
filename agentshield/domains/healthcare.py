"""Healthcare domain plugin — extends keywords, redactions, and provides factory."""

from __future__ import annotations

from agentshield.defense.prompt_guard import DOMAIN_KEYWORDS, PromptInjectionGuard
from agentshield.defense.output_filter import DOMAIN_REDACTIONS, OutputFilter
from agentshield.defense.rag_shield import RAGShield

# ------------------------------------------------------------------
# Extend (not replace) the healthcare keyword list
# ------------------------------------------------------------------

DOMAIN_KEYWORDS.setdefault("healthcare", []).extend([
    "tumor", "cancer", "cardiology", "oncology",
    "radiology", "pathology", "pediatrics", "psychiatry",
    "allergy", "orthopedics", "dermatology", "hematology",
])

# ------------------------------------------------------------------
# Extend healthcare redaction patterns
# ------------------------------------------------------------------

DOMAIN_REDACTIONS.setdefault("healthcare", []).extend([
    (r"\b\d{10}(?:NPI)?\b", "[NPI_REDACTED]"),          # NPI number
    (r"\b[A-Z]\d{2}(?:\.\d{1,2})?\b", "[ICD10_REDACTED]"),  # ICD-10 diagnosis code
])

# ------------------------------------------------------------------
# Trusted medical domains for RAG source validation
# ------------------------------------------------------------------

TRUSTED_MEDICAL_DOMAINS: list[str] = [
    "mayoclinic.org",
    "nih.gov",
    "cdc.gov",
    "who.int",
    "medlineplus.gov",
    "uptodate.com",
    "pubmed.ncbi.nlm.nih.gov",
    "nejm.org",
    "jamanetwork.com",
    "bmj.com",
]


def create_healthcare_shield(
    trusted_rag_domains: list[str] | None = None,
) -> tuple[PromptInjectionGuard, RAGShield, OutputFilter]:
    """Create a pre-configured healthcare defence stack.

    Returns:
        A tuple of ``(PromptInjectionGuard, RAGShield, OutputFilter)`` ready to use.
    """
    domains = trusted_rag_domains if trusted_rag_domains is not None else list(TRUSTED_MEDICAL_DOMAINS)
    return (
        PromptInjectionGuard(domain="healthcare"),
        RAGShield(trusted_domains=domains),
        OutputFilter(domain="healthcare"),
    )
