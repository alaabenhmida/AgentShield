"""RAG Shield — scans retrieved documents for injections and integrity violations."""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field

from agentshield.core.types import ThreatLevel  # only used for type reference

log = logging.getLogger("agentshield.rag_shield")

# ======================================================================
# Injection patterns for document content  (pre-compiled)
# ======================================================================

_INJECTION_PATTERN_DEFS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "doc_injection_override"),
    (r"\[SYSTEM\]|\[ADMIN\]", "doc_fake_system_tag"),
    (r"you\s+are\s+now", "doc_persona_override"),
    (r"(reveal|show|print)\s+(your\s+)?system\s+prompt", "doc_prompt_leak"),
    (r"<!--[\s\S]*?-->", "html_comment_hiding"),
    (r"<script", "script_injection"),
]

INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p, re.IGNORECASE), lbl) for p, lbl in _INJECTION_PATTERN_DEFS
]


@dataclass
class DocumentScanResult:
    """Result of scanning a single retrieved document."""
    is_safe: bool
    document: str
    source: str
    flags: list[str] = field(default_factory=list)
    original_hash: str = ""
    current_hash: str = ""

    @property
    def was_tampered(self) -> bool:
        """True if both hashes are set and they differ."""
        return bool(self.original_hash and self.current_hash and self.original_hash != self.current_hash)


class RAGShield:
    """Validates and sanitises documents retrieved by RAG pipelines."""

    def __init__(
        self,
        trusted_domains: list[str] | None = None,
        known_hashes: dict[str, str] | None = None,
    ) -> None:
        self._trusted_domains = set(trusted_domains or [])
        self._known_hashes: dict[str, str] = dict(known_hashes or {})

    def filter_documents(
        self,
        documents: list[str],
        sources: list[str] | None = None,
    ) -> list[str]:
        """Return only safe (possibly sanitised) documents."""
        if sources is None:
            sources = ["unknown"] * len(documents)
        safe: list[str] = []
        for doc, src in zip(documents, sources):
            result = self.scan_document(doc, source=src)
            if result.is_safe:
                safe.append(result.document)
        return safe

    def scan_document(self, document: str, source: str = "unknown") -> DocumentScanResult:
        """Scan a single document for injection attempts and integrity issues."""
        flags: list[str] = []
        sanitized = document

        # 1 — Source allow-list check
        if self._trusted_domains and source != "unknown":
            trusted = any(domain in source for domain in self._trusted_domains)
            if not trusted:
                flags.append(f"untrusted_source:{source}")

        # 2 — Injection pattern scan
        lowered = document.lower()
        for compiled, label in INJECTION_PATTERNS:
            if compiled.search(lowered):
                flags.append(label)
                sanitized = compiled.sub("[REDACTED]", sanitized)

        # 3 — Integrity check
        current_hash = self._hash(document)
        original_hash = self._known_hashes.get(source, "")

        if original_hash and original_hash != current_hash:
            flags.append("integrity_mismatch")

        is_safe = not any(
            f for f in flags
            if f not in [f"untrusted_source:{source}"]  # untrusted source alone doesn't block
            or f == "integrity_mismatch"
            or not f.startswith("untrusted_source:")
        )
        # Simpler logic: unsafe if any injection or integrity flag
        injection_flags = [f for f in flags if not f.startswith("untrusted_source:")]
        is_safe = len(injection_flags) == 0

        return DocumentScanResult(
            is_safe=is_safe,
            document=sanitized,
            source=source,
            flags=flags,
            original_hash=original_hash,
            current_hash=current_hash,
        )

    def register_document(self, source: str, document: str) -> str:
        """Register a document's SHA-256 hash for later integrity checks."""
        h = self._hash(document)
        self._known_hashes[source] = h
        return h

    @staticmethod
    def _hash(text: str) -> str:
        """Return the SHA-256 hex digest of *text*."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
