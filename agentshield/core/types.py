"""Core type definitions for AgentShield. Zero imports from other agentshield modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ThreatLevel(str, Enum):
    """Severity classification for detected threats."""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    CRITICAL = "CRITICAL"


class AttackCategory(str, Enum):
    """Categories of attacks used in red-team simulations."""
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    RAG_POISONING = "RAG_POISONING"
    ROLE_MANIPULATION = "ROLE_MANIPULATION"
    MULTI_TURN_ESCALATION = "MULTI_TURN_ESCALATION"
    AGENT_HIJACKING = "AGENT_HIJACKING"
    CROSS_AGENT_LEAK = "CROSS_AGENT_LEAK"
    TOOL_ABUSE = "TOOL_ABUSE"
    ROUTING_MANIPULATION = "ROUTING_MANIPULATION"


@dataclass
class AgentResponse:
    """Standardised response envelope returned by every adapter."""
    output: str
    raw_response: Any = None
    agents_involved: list[str] = field(default_factory=list)
    tools_called: list[str] = field(default_factory=list)
    context_retrieved: list[str] = field(default_factory=list)
    intermediate_steps: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class ThreatAnalysis:
    """Result of analysing a user message for threats."""
    threat_level: ThreatLevel
    score: float
    matched_patterns: list[str] = field(default_factory=list)
    structural_flags: list[str] = field(default_factory=list)
    domain_relevant: bool = True
    anomaly_flags: list[str] = field(default_factory=list)
    sanitized_input: str | None = None

    @property
    def is_blocked(self) -> bool:
        """True when the threat level is MALICIOUS or CRITICAL."""
        return self.threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL)


@dataclass
class FilteredOutput:
    """Result of scanning an agent response for data leaks."""
    text: str
    redactions: list[str] = field(default_factory=list)
    had_leaks: bool = False


@dataclass
class AttackResult:
    """Outcome of a single red-team attack probe."""
    attack_id: str
    category: AttackCategory
    payload: str
    blocked_by_guard: bool
    response: str
    blocked_by_output_filter: bool
    success_indicators_found: list[str] = field(default_factory=list)
    failure_indicators_found: list[str] = field(default_factory=list)
    bypassed: bool = False
    is_multi_turn: bool = False
    turn_results: list[dict] = field(default_factory=list)


@dataclass
class SimulationReport:
    """Aggregate results of a full red-team simulation run."""
    total_attacks: int
    blocked: int
    bypassed: int
    score: float
    category_scores: dict[str, float] = field(default_factory=dict)
    results: list[AttackResult] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    system_info: dict = field(default_factory=dict)
