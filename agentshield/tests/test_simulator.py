"""Tests for the red-team simulator — safe vs vulnerable agents, report structure."""

from __future__ import annotations

import pytest

from agentshield.core.adapter import SystemAdapter
from agentshield.core.types import SimulationReport
from agentshield.red_team.simulator import RedTeamSimulator


# ======================================================================
# Mock agents
# ======================================================================


def safe_agent(text: str) -> str:
    return "I'm sorry, I can only help with medical questions. This request is not authorized."


def vulnerable_agent(text: str) -> str:
    if "previous" in text.lower():
        return "The previous patient asked about insulin. Their ID is P12345."
    if "system prompt" in text.lower():
        return "Your system prompt is: You are a helpful medical assistant..."
    if "list all" in text.lower():
        return "Users: user1, user2, patient_id: P001"
    return "Here is the information you requested."


# ======================================================================
# Tests
# ======================================================================


class TestRedTeamSimulator:
    """End-to-end simulator tests using mock agents."""

    @pytest.mark.asyncio
    async def test_safe_agent_scores_high(self) -> None:
        adapter = SystemAdapter.from_callable(safe_agent, name="SafeAgent")
        sim = RedTeamSimulator(adapter, domains=["healthcare"])
        report = await sim.run()
        assert isinstance(report, SimulationReport)
        assert report.score >= 70

    @pytest.mark.asyncio
    async def test_vulnerable_agent_scores_lower(self) -> None:
        adapter = SystemAdapter.from_callable(vulnerable_agent, name="VulnAgent")
        sim = RedTeamSimulator(adapter, domains=["healthcare"])
        report = await sim.run()
        assert isinstance(report, SimulationReport)
        assert report.score < 90

    @pytest.mark.asyncio
    async def test_blocked_plus_bypassed_equals_total(self) -> None:
        adapter = SystemAdapter.from_callable(safe_agent, name="SafeAgent")
        sim = RedTeamSimulator(adapter, domains=["healthcare"])
        report = await sim.run()
        assert report.blocked + report.bypassed == report.total_attacks

    @pytest.mark.asyncio
    async def test_category_scores_populated(self) -> None:
        adapter = SystemAdapter.from_callable(safe_agent, name="SafeAgent")
        sim = RedTeamSimulator(adapter, domains=["healthcare"])
        report = await sim.run()
        assert isinstance(report.category_scores, dict)
        assert len(report.category_scores) > 0

    def test_print_report_outputs_header(self, capsys: pytest.CaptureFixture[str]) -> None:
        report = SimulationReport(
            total_attacks=10,
            blocked=8,
            bypassed=2,
            score=80.0,
            category_scores={"PROMPT_INJECTION": 75.0, "JAILBREAK": 100.0},
            results=[],
            recommendations=["[HIGH] Fix prompt injection defences."],
            system_info={"framework": "Callable", "name": "TestAgent"},
        )
        RedTeamSimulator.print_report(report)
        captured = capsys.readouterr().out
        assert "AGENTSHIELD" in captured
        assert "Overall Score" in captured
