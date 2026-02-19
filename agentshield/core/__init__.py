"""AgentShield core module — types, adapters, middleware, config, and shield orchestration."""

from __future__ import annotations

from agentshield.core.types import (
    AgentResponse,
    ThreatLevel,
    ThreatAnalysis,
    FilteredOutput,
    AttackCategory,
    AttackResult,
    SimulationReport,
)
from agentshield.core.adapter import SystemAdapter, SystemAdapterProtocol
from agentshield.core.shield import AgentShield, ShieldConfig
from agentshield.core.middleware import Middleware, MiddlewareChain, ShieldContext
from agentshield.core.config import load_config_dict

__all__ = [
    "AgentResponse",
    "ThreatLevel",
    "ThreatAnalysis",
    "FilteredOutput",
    "AttackCategory",
    "AttackResult",
    "SimulationReport",
    "SystemAdapter",
    "SystemAdapterProtocol",
    "AgentShield",
    "ShieldConfig",
    "Middleware",
    "MiddlewareChain",
    "ShieldContext",
    "load_config_dict",
]
