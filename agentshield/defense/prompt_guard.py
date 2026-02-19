"""Prompt-injection detection — four-layer analysis pipeline."""

from __future__ import annotations

import base64
import logging
import math
import re
from collections import Counter

from agentshield.core.types import ThreatAnalysis, ThreatLevel

log = logging.getLogger("agentshield.prompt_guard")

# ======================================================================
# Pattern databases  (pre-compiled for performance)
# ======================================================================

_UNIVERSAL_PATTERN_DEFS: list[tuple[str, str, float]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "direct_override", 0.9),
    (r"disregard\s+(your|all|previous)\s+", "direct_override", 0.9),
    (r"you\s+are\s+(now\s+)?(DAN|an?\s+AI\s+without|uncensored)", "jailbreak_persona", 0.9),
    (r"(show|reveal|print|display|repeat)\s+(me\s+)?(your|the)\s+system\s+prompt", "system_prompt_leak", 0.95),
    (r"list\s+all\s+(patients?|users?|accounts?|records?)", "data_enumeration", 0.85),
    (r"what\s+did\s+(the\s+)?(previous|last|other)\s+(patient|user)\s+ask", "cross_session_leak", 0.85),
    (r"\[SYSTEM\]|\[ADMIN\]|\[ROOT\]", "fake_system_tag", 0.8),
    (r"(act|pretend|behave)\s+as\s+(if\s+)?(you\s+are|you're|you were)", "persona_override", 0.7),
    (r"base64|b64decode|atob\(", "encoding_attack", 0.75),
    (r"for\s+(educational|research|hypothetical)\s+purposes?.*prescri", "hypothetical_jailbreak", 0.8),
]

_STRUCTURAL_PATTERN_DEFS: list[tuple[str, str, float]] = [
    (r"-{3,}|={3,}|\*{3,}", "delimiter_injection", 0.6),
    (r'\{[\s\S]*?["\']role["\']\s*:\s*["\']system["\']', "json_role_injection", 0.9),
    (r"(\n\s*){5,}", "excessive_newlines", 0.4),
    (r"SYSTEM:|ASSISTANT:|USER:", "fake_chat_marker", 0.7),
]

# Pre-compiled pattern tuples: (compiled_re, label, weight)
UNIVERSAL_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(p, re.IGNORECASE), lbl, w) for p, lbl, w in _UNIVERSAL_PATTERN_DEFS
]

STRUCTURAL_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(p, re.IGNORECASE), lbl, w) for p, lbl, w in _STRUCTURAL_PATTERN_DEFS
]

_B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_SANITIZE_TAGS_RE = re.compile(r"\[SYSTEM\]|\[ADMIN\]|\[ROOT\]", re.IGNORECASE)
_SANITIZE_DASHES_RE = re.compile(r"-{3,}")
_SANITIZE_EQUALS_RE = re.compile(r"={3,}")

DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "healthcare": [
        "diabetes", "hypertension", "medication", "symptom", "diagnosis",
        "treatment", "patient", "chronic", "disease", "prescription",
        "doctor", "hospital", "blood pressure", "insulin", "cardiovascular",
    ],
    "finance": [
        "account", "balance", "transaction", "investment", "portfolio",
        "credit", "loan", "interest", "payment", "stock", "fund",
    ],
    "legal": [
        "contract", "clause", "liability", "regulation", "compliance",
        "lawsuit", "attorney", "court", "jurisdiction", "precedent",
    ],
    "general": [],
}


# ======================================================================
# Guard implementation
# ======================================================================


class PromptInjectionGuard:
    """Four-layer prompt-injection detector.

    Layer A — regex pattern matching (+ base64 decode check)
    Layer B — structural anomaly detection
    Layer C — domain relevance check
    Layer D — statistical anomaly (entropy, special char ratio)
    """

    BLOCK_THRESHOLD = 0.65
    SUSPICIOUS_THRESHOLD = 0.35

    def __init__(self, domain: str = "general") -> None:
        self._domain = domain
        self._keywords = DOMAIN_KEYWORDS.get(domain, [])

    async def analyze(self, text: str) -> ThreatAnalysis:
        """Run all four layers and return a consolidated :class:`ThreatAnalysis`."""
        score_a, labels_a = self._layer_a_patterns(text)
        score_b, flags_b = self._layer_b_structural(text)
        domain_relevant = self._layer_c_domain(text)
        score_d, flags_d = self._layer_d_anomaly(text)

        raw = score_a + score_b + score_d
        total_score = self._sigmoid_normalize(raw)

        if total_score >= 0.9:
            level = ThreatLevel.CRITICAL
        elif total_score >= self.BLOCK_THRESHOLD:
            level = ThreatLevel.MALICIOUS
        elif total_score >= self.SUSPICIOUS_THRESHOLD:
            level = ThreatLevel.SUSPICIOUS
        else:
            level = ThreatLevel.SAFE

        sanitized: str | None = None
        if level == ThreatLevel.SUSPICIOUS:
            sanitized = self._sanitize(text)

        return ThreatAnalysis(
            threat_level=level,
            score=total_score,
            matched_patterns=labels_a,
            structural_flags=flags_b,
            domain_relevant=domain_relevant,
            anomaly_flags=flags_d,
            sanitized_input=sanitized,
        )

    # ------------------------------------------------------------------
    # Score normalisation (sigmoid)
    # ------------------------------------------------------------------

    @staticmethod
    def _sigmoid_normalize(raw: float, midpoint: float = 0.65, steepness: float = 8.0) -> float:
        """Map a raw additive score onto [0, 1] via a sigmoid curve.

        The curve is centred at *midpoint* (where it outputs ~0.5) and
        *steepness* controls how quickly values near the midpoint saturate.
        This gives a more interpretable score than a simple ``min(raw, 1.0)``
        clamp and avoids score inflation from multiple weak signals.
        """
        return 1.0 / (1.0 + math.exp(-steepness * (raw - midpoint)))

    # ------------------------------------------------------------------
    # Layer A — pattern + base64
    # ------------------------------------------------------------------

    def _layer_a_patterns(self, text: str) -> tuple[float, list[str]]:
        lowered = text.lower()
        score = 0.0
        labels: list[str] = []

        # Check for hidden base64 tokens
        for match in _B64_RE.finditer(text):
            try:
                decoded = base64.b64decode(match.group(), validate=True).decode("utf-8", errors="ignore").lower()
                danger_words = ["ignore", "system", "admin", "override", "prompt", "password"]
                if any(w in decoded for w in danger_words):
                    score += 0.8
                    labels.append("base64_hidden_payload")
            except Exception:
                pass

        for compiled, label, weight in UNIVERSAL_PATTERNS:
            if compiled.search(lowered):
                score += weight
                labels.append(label)

        return score, labels

    # ------------------------------------------------------------------
    # Layer B — structural
    # ------------------------------------------------------------------

    def _layer_b_structural(self, text: str) -> tuple[float, list[str]]:
        score = 0.0
        flags: list[str] = []

        for compiled, label, weight in STRUCTURAL_PATTERNS:
            if compiled.search(text):
                score += weight
                flags.append(label)

        if len(text) > 2000:
            score += 0.2
            flags.append("excessive_length")

        return score, flags

    # ------------------------------------------------------------------
    # Layer C — domain relevance
    # ------------------------------------------------------------------

    def _layer_c_domain(self, text: str) -> bool:
        if not self._keywords:
            return True
        lowered = text.lower()
        return any(kw in lowered for kw in self._keywords)

    # ------------------------------------------------------------------
    # Layer D — statistical anomaly
    # ------------------------------------------------------------------

    def _layer_d_anomaly(self, text: str) -> tuple[float, list[str]]:
        score = 0.0
        flags: list[str] = []

        entropy = self._shannon_entropy(text)
        if entropy > 5.5:
            score += 0.15
            flags.append(f"high_entropy:{entropy:.2f}")

        if text:
            special = sum(1 for c in text if not c.isalnum() and not c.isspace())
            ratio = special / len(text)
            if ratio > 0.3:
                score += 0.15
                flags.append(f"high_special_char_ratio:{ratio:.2f}")

        return score, flags

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    @staticmethod
    def _sanitize(text: str) -> str:
        """Strip known dangerous markers from input."""
        cleaned = _SANITIZE_TAGS_RE.sub("", text)
        cleaned = _SANITIZE_DASHES_RE.sub("", cleaned)
        cleaned = _SANITIZE_EQUALS_RE.sub("", cleaned)
        return cleaned.strip()
