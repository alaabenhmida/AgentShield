"""Shield orchestrator — runs the middleware-based defense pipeline.

The default pipeline consists of four built-in middlewares executed in order:

1. ``PromptGuardMiddleware``  — analyse input for injections / jailbreaks
2. ``BoundaryMiddleware``     — wrap input with security tokens
3. ``InvokeMiddleware``       — call the underlying agent system
4. ``OutputFilterMiddleware``  — redact PII / credentials / leaks

Users can customise the pipeline via :pyattr:`AgentShield.chain`:

- ``shield.chain.insert_before("invoke", MyCustomMiddleware())``
- ``shield.chain.remove("boundary")``
- ``shield.chain.replace("output_filter", MyBetterFilter())``

Or pass a fully custom ``middlewares`` list to skip the defaults entirely.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from agentshield.core.types import AgentResponse, ThreatLevel
from agentshield.core.middleware import Middleware, MiddlewareChain, ShieldContext

log = logging.getLogger("agentshield.shield")

# Type alias for event callbacks
EventCallback = Callable[..., Any]


@dataclass
class ShieldConfig:
    """Configuration knobs for :class:`AgentShield`."""
    domain: str = "general"
    block_threshold: ThreatLevel = ThreatLevel.MALICIOUS
    enforce_boundaries: bool = True
    filter_output: bool = True
    log_incidents: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> "ShieldConfig":
        """Build a config from a plain dict (e.g. parsed from YAML/JSON)."""
        return cls(
            domain=data.get("domain", "general"),
            block_threshold=ThreatLevel(data["block_threshold"]) if "block_threshold" in data else ThreatLevel.MALICIOUS,
            enforce_boundaries=data.get("enforce_boundaries", True),
            filter_output=data.get("filter_output", True),
            log_incidents=data.get("log_incidents", True),
        )


class AgentShield:
    """Main entry-point — wraps any :class:`SystemAdapter` with defence layers.

    The processing pipeline is implemented as a :class:`MiddlewareChain`.
    By default the chain contains:

    1. ``PromptGuardMiddleware``   (name ``"prompt_guard"``)
    2. ``BoundaryMiddleware``      (name ``"boundary"``)
    3. ``InvokeMiddleware``        (name ``"invoke"``)
    4. ``OutputFilterMiddleware``  (name ``"output_filter"``)

    Pass a custom ``middlewares`` sequence to override the defaults, or
    mutate ``shield.chain`` after construction.
    """

    def __init__(
        self,
        adapter: object,
        domain: str = "general",
        config: ShieldConfig | None = None,
        middlewares: Sequence[Middleware] | None = None,
    ) -> None:
        self._adapter = adapter
        self._config = config or ShieldConfig(domain=domain)
        self._incidents: list[dict] = []
        self._sessions: dict[str, list[dict]] = {}
        self._callbacks: dict[str, list[EventCallback]] = {}

        if middlewares is not None:
            self._chain = MiddlewareChain(list(middlewares))
        else:
            self._chain = self._default_chain()

    # ------------------------------------------------------------------
    # Event / webhook hooks
    # ------------------------------------------------------------------

    def on(self, event: str, callback: EventCallback) -> None:
        """Register a callback for *event*.

        Supported events: ``"before_run"``, ``"after_run"``, ``"on_block"``,
        ``"on_incident"``.
        """
        self._callbacks.setdefault(event, []).append(callback)

    def _emit(self, event: str, **kwargs: Any) -> None:
        for cb in self._callbacks.get(event, []):
            try:
                cb(**kwargs)
            except Exception:                       # noqa: BLE001
                log.exception("Error in '%s' callback", event)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def chain(self) -> MiddlewareChain:
        """The live middleware chain — mutate to customise the pipeline."""
        return self._chain

    @property
    def incidents(self) -> list[dict]:
        """Return logged security incidents."""
        return list(self._incidents)

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    def get_session(self, session_id: str) -> list[dict]:
        """Return the interaction history for *session_id*."""
        return list(self._sessions.get(session_id, []))

    # ------------------------------------------------------------------
    # Core run method
    # ------------------------------------------------------------------

    async def run(
        self,
        user_input: str,
        *,
        session_id: str | None = None,
    ) -> AgentResponse:
        """Execute the full middleware pipeline and return the response."""
        self._emit("before_run", user_input=user_input, session_id=session_id)

        ctx = ShieldContext(
            user_input=user_input,
            domain=self._config.domain,
        )

        ctx = await self._chain.execute(ctx)

        # Collect incidents from the context into the shield-level list.
        if self._config.log_incidents:
            for inc in ctx.incidents:
                self._incidents.append(inc)
                self._emit("on_incident", incident=inc)
                log.warning("Security incident: %s", inc)

        if ctx.blocked:
            self._emit("on_block", reason=ctx.block_reason, user_input=user_input)
            log.info("Blocked request: %s", ctx.block_reason)

        response = ctx.response or AgentResponse(
            output="",
            error="No response produced — check middleware chain configuration.",
        )

        # Session tracking
        if session_id is not None:
            self._sessions.setdefault(session_id, []).append({
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "input": user_input,
                "output": response.output,
                "blocked": ctx.blocked,
                "threat_score": ctx.threat_analysis.score if ctx.threat_analysis else 0.0,
            })

        self._emit("after_run", response=response, session_id=session_id)
        return response

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _default_chain(self) -> MiddlewareChain:
        """Build the standard 4-layer middleware chain."""
        from agentshield.defense.middlewares import (
            PromptGuardMiddleware,
            BoundaryMiddleware,
            InvokeMiddleware,
            OutputFilterMiddleware,
        )

        layers: list[Middleware] = [
            PromptGuardMiddleware(domain=self._config.domain),
        ]
        if self._config.enforce_boundaries:
            layers.append(BoundaryMiddleware())
        layers.append(InvokeMiddleware(self._adapter))
        if self._config.filter_output:
            layers.append(OutputFilterMiddleware(domain=self._config.domain))

        return MiddlewareChain(layers)
