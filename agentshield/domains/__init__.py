"""Domain plugins — pre-configured defence stacks for specific industries."""

from __future__ import annotations

from agentshield.domains.healthcare import create_healthcare_shield, TRUSTED_MEDICAL_DOMAINS
from agentshield.domains.finance import create_finance_shield, TRUSTED_FINANCE_DOMAINS
from agentshield.domains.legal import create_legal_shield, TRUSTED_LEGAL_DOMAINS

__all__ = [
    "create_healthcare_shield",
    "TRUSTED_MEDICAL_DOMAINS",
    "create_finance_shield",
    "TRUSTED_FINANCE_DOMAINS",
    "create_legal_shield",
    "TRUSTED_LEGAL_DOMAINS",
]
