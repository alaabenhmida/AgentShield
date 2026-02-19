"""
AgentShield — Security framework for multi-agent AI systems.

AgentShield provides production defense and pre-production red teaming
for any multi-agent system (LangGraph, CrewAI, LangChain, or plain Python).

Quick Start — Production Defense:

    import asyncio
    from agentshield import AgentShield, SystemAdapter

    def my_agent(text: str) -> str:
        return f"Response to: {text}"

    adapter = SystemAdapter.from_callable(my_agent, name="MyAgent")
    shield = AgentShield(adapter, domain="general")

    response = asyncio.run(shield.run("Hello, how are you?"))
    print(response.output)

Quick Start — Red Teaming:

    import asyncio
    from agentshield import SystemAdapter
    from agentshield.red_team import RedTeamSimulator

    def my_agent(text: str) -> str:
        return "I can only help with allowed topics."

    adapter = SystemAdapter.from_callable(my_agent, name="MyAgent")
    simulator = RedTeamSimulator(adapter, domains=["general"], verbose=True)

    report = asyncio.run(simulator.run())
    RedTeamSimulator.print_report(report)
"""

from __future__ import annotations

from agentshield.core.shield import AgentShield, ShieldConfig
from agentshield.core.adapter import SystemAdapter, SystemAdapterProtocol
from agentshield.core.middleware import Middleware, MiddlewareChain, ShieldContext
from agentshield.core.config import load_config_dict
from agentshield.core.types import (
    AgentResponse,
    ThreatLevel,
    ThreatAnalysis,
    FilteredOutput,
    AttackCategory,
    AttackResult,
    SimulationReport,
)

__version__ = "0.1.0"

__all__ = [
    "AgentShield",
    "ShieldConfig",
    "SystemAdapter",
    "SystemAdapterProtocol",
    "Middleware",
    "MiddlewareChain",
    "ShieldContext",
    "load_config_dict",
    "AgentResponse",
    "ThreatLevel",
    "ThreatAnalysis",
    "FilteredOutput",
    "AttackCategory",
    "AttackResult",
    "SimulationReport",
    "__version__",
]
