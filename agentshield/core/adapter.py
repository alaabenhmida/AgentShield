"""Adapter layer — uniform interface for any multi-agent framework.

Both a structural :class:`Protocol` (``SystemAdapterProtocol``) and an
:class:`ABC` (``SystemAdapter``) are provided.  The ABC offers convenience
factory methods; the Protocol lets plain duck-typed objects participate
without inheriting from anything.
"""

from __future__ import annotations

import abc
import asyncio
import inspect
from typing import Any, Callable, Protocol, runtime_checkable

from agentshield.core.types import AgentResponse


@runtime_checkable
class SystemAdapterProtocol(Protocol):
    """Structural (duck-typed) protocol for system adapters.

    Any object that implements ``invoke`` and ``get_system_info`` satisfies
    this protocol — no inheritance required.
    """

    async def invoke(self, user_input: str) -> AgentResponse: ...
    def get_system_info(self) -> dict: ...


class SystemAdapter(abc.ABC):
    """Abstract base class that normalises every AI system behind a single
    ``invoke`` / ``invoke_sync`` interface."""

    @abc.abstractmethod
    async def invoke(self, user_input: str) -> AgentResponse:
        """Send *user_input* through the wrapped system and return a response."""

    @abc.abstractmethod
    def get_system_info(self) -> dict:
        """Return metadata about the wrapped system."""

    def invoke_sync(self, user_input: str) -> AgentResponse:
        """Blocking convenience wrapper around :meth:`invoke`."""
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, self.invoke(user_input)).result()
        return loop.run_until_complete(self.invoke(user_input))

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @staticmethod
    def for_langgraph(
        graph: Any,
        config: dict | None = None,
        input_key: str = "messages",
        output_key: str = "messages",
    ) -> "LangGraphAdapter":
        """Create an adapter for a LangGraph compiled graph."""
        return LangGraphAdapter(graph, config=config, input_key=input_key, output_key=output_key)

    @staticmethod
    def for_crewai(crew: Any) -> "CrewAIAdapter":
        """Create an adapter for a CrewAI crew."""
        return CrewAIAdapter(crew)

    @staticmethod
    def for_langchain(agent: Any, input_key: str = "input") -> "LangChainAdapter":
        """Create an adapter for a LangChain agent executor."""
        return LangChainAdapter(agent, input_key=input_key)

    @staticmethod
    def from_callable(fn: Callable, name: str = "CustomAgent") -> "CallableAdapter":
        """Wrap any plain Python callable (sync or async) as an adapter."""
        return CallableAdapter(fn, name=name)


# ======================================================================
# Concrete adapters
# ======================================================================


class LangGraphAdapter(SystemAdapter):
    """Adapter for LangGraph compiled graphs."""

    def __init__(
        self,
        graph: Any,
        config: dict | None = None,
        input_key: str = "messages",
        output_key: str = "messages",
    ) -> None:
        self._graph = graph
        self._config = config or {}
        self._input_key = input_key
        self._output_key = output_key

    async def invoke(self, user_input: str) -> AgentResponse:
        try:
            payload = {self._input_key: [{"role": "user", "content": user_input}]}
            if hasattr(self._graph, "ainvoke"):
                state = await self._graph.ainvoke(payload, config=self._config)
            else:
                state = await asyncio.to_thread(self._graph.invoke, payload, config=self._config)

            # Extract output
            messages = state.get(self._output_key, [])
            if messages:
                last = messages[-1]
                if isinstance(last, dict):
                    output = last.get("content", str(last))
                elif hasattr(last, "content"):
                    output = last.content
                else:
                    output = str(last)
            else:
                output = str(state)

            # Extract optional metadata
            agents_involved = state.get("agents_involved", [])
            if not agents_involved:
                agents_involved = [str(a) for a in state.get("agents", [])]

            tools_called = state.get("tools_called", [])
            context_retrieved = state.get("retrieved_docs", [])
            intermediate_steps = [str(s) for s in state.get("intermediate_steps", [])]

            return AgentResponse(
                output=output,
                raw_response=state,
                agents_involved=agents_involved,
                tools_called=tools_called,
                context_retrieved=context_retrieved,
                intermediate_steps=intermediate_steps,
            )
        except Exception as exc:
            return AgentResponse(output="", error=str(exc))

    def get_system_info(self) -> dict:
        return {
            "framework": "LangGraph",
            "graph_type": type(self._graph).__name__,
            "config": self._config,
        }


class CrewAIAdapter(SystemAdapter):
    """Adapter for CrewAI crews."""

    def __init__(self, crew: Any) -> None:
        self._crew = crew

    async def invoke(self, user_input: str) -> AgentResponse:
        try:
            result = await asyncio.to_thread(
                self._crew.kickoff, inputs={"query": user_input}
            )
            if hasattr(result, "raw"):
                output = result.raw
            else:
                output = str(result)

            agents_involved: list[str] = []
            if hasattr(self._crew, "agents"):
                for agent in self._crew.agents:
                    if hasattr(agent, "role"):
                        agents_involved.append(agent.role)
                    else:
                        agents_involved.append(str(agent))

            return AgentResponse(
                output=output,
                raw_response=result,
                agents_involved=agents_involved,
            )
        except Exception as exc:
            return AgentResponse(output="", error=str(exc))

    def get_system_info(self) -> dict:
        agent_roles: list[str] = []
        if hasattr(self._crew, "agents"):
            for agent in self._crew.agents:
                agent_roles.append(getattr(agent, "role", str(agent)))
        return {
            "framework": "CrewAI",
            "agent_roles": agent_roles,
        }


class LangChainAdapter(SystemAdapter):
    """Adapter for LangChain agent executors or chains."""

    def __init__(self, agent: Any, input_key: str = "input") -> None:
        self._agent = agent
        self._input_key = input_key

    async def invoke(self, user_input: str) -> AgentResponse:
        try:
            payload = {self._input_key: user_input}
            if hasattr(self._agent, "ainvoke"):
                result = await self._agent.ainvoke(payload)
            else:
                result = await asyncio.to_thread(self._agent.invoke, payload)

            if isinstance(result, dict):
                output = result.get("output", str(result))
                intermediate_steps = [str(s) for s in result.get("intermediate_steps", [])]
            else:
                output = str(result)
                intermediate_steps = []

            return AgentResponse(
                output=output,
                raw_response=result,
                intermediate_steps=intermediate_steps,
            )
        except Exception as exc:
            return AgentResponse(output="", error=str(exc))

    def get_system_info(self) -> dict:
        return {
            "framework": "LangChain",
            "agent_type": type(self._agent).__name__,
        }


class CallableAdapter(SystemAdapter):
    """Adapter for arbitrary sync/async Python callables."""

    def __init__(self, fn: Callable, name: str = "CustomAgent") -> None:
        self._fn = fn
        self._name = name

    async def invoke(self, user_input: str) -> AgentResponse:
        try:
            if inspect.iscoroutinefunction(self._fn):
                result = await self._fn(user_input)
            else:
                result = await asyncio.to_thread(self._fn, user_input)
            return AgentResponse(output=str(result))
        except Exception as exc:
            return AgentResponse(output="", error=str(exc))

    def get_system_info(self) -> dict:
        return {"framework": "Callable", "name": self._name}
