"""Tests for adapter layer — callable adapters and system info."""

from __future__ import annotations

import pytest

from agentshield.core.adapter import SystemAdapter
from agentshield.core.types import AgentResponse


# ======================================================================
# Mock callables
# ======================================================================


def sync_echo(text: str) -> str:
    return f"Echo: {text}"


async def async_echo(text: str) -> str:
    return f"AsyncEcho: {text}"


def failing_fn(text: str) -> str:
    raise RuntimeError("Simulated failure")


# ======================================================================
# TestCallableAdapter
# ======================================================================


class TestCallableAdapter:
    """Tests for the CallableAdapter created via ``SystemAdapter.from_callable``."""

    def test_from_callable_system_info(self) -> None:
        adapter = SystemAdapter.from_callable(sync_echo, name="TestEcho")
        info = adapter.get_system_info()
        assert "framework" in info
        assert "name" in info
        assert info["framework"] == "Callable"
        assert info["name"] == "TestEcho"

    @pytest.mark.asyncio
    async def test_invoke_returns_agent_response(self) -> None:
        adapter = SystemAdapter.from_callable(sync_echo, name="TestEcho")
        result = await adapter.invoke("hello")
        assert isinstance(result, AgentResponse)
        assert result.output == "Echo: hello"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_async_callable_supported(self) -> None:
        adapter = SystemAdapter.from_callable(async_echo, name="AsyncEcho")
        result = await adapter.invoke("world")
        assert isinstance(result, AgentResponse)
        assert result.output == "AsyncEcho: world"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_failing_fn_returns_error_without_raising(self) -> None:
        adapter = SystemAdapter.from_callable(failing_fn, name="FailAgent")
        result = await adapter.invoke("test")
        assert isinstance(result, AgentResponse)
        assert result.error is not None
        assert "Simulated failure" in result.error
        assert result.output == ""

    def test_invoke_sync_convenience(self) -> None:
        adapter = SystemAdapter.from_callable(sync_echo, name="SyncTest")
        result = adapter.invoke_sync("sync test")
        assert isinstance(result, AgentResponse)
        assert result.output == "Echo: sync test"


# ======================================================================
# TestAdapterSystemInfo
# ======================================================================


class TestAdapterSystemInfo:
    """Tests for ``get_system_info`` across adapter types."""

    def test_callable_system_info(self) -> None:
        adapter = SystemAdapter.from_callable(sync_echo, name="InfoTest")
        info = adapter.get_system_info()
        assert info["framework"] == "Callable"
        assert info["name"] == "InfoTest"
