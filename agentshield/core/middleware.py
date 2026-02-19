"""Middleware pipeline — composable, reorderable processing layers.

The middleware system lets users inject, remove, or reorder security layers
without modifying ``AgentShield`` internals.  Each middleware receives a
:class:`ShieldContext` and a ``next_fn`` coroutine that calls the next
middleware in the chain (or the terminal handler).

Example — custom rate-limiter middleware::

    from agentshield.core.middleware import Middleware, ShieldContext

    class RateLimiter(Middleware):
        name = "rate_limiter"

        async def process(self, ctx: ShieldContext, next_fn):
            if self._is_rate_limited(ctx.user_input):
                ctx.blocked = True
                ctx.block_reason = "Rate limit exceeded."
                return ctx
            return await next_fn(ctx)
"""

from __future__ import annotations

import abc
import datetime
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from agentshield.core.types import AgentResponse, ThreatAnalysis


# ======================================================================
# Context object that flows through the middleware chain
# ======================================================================

@dataclass
class ShieldContext:
    """Mutable bag of state that flows through every middleware.

    Middlewares read and write fields on this object.  The context starts
    with ``user_input`` populated and ends (if not blocked) with
    ``response`` populated.
    """

    # --- input side ---
    user_input: str
    effective_input: str = ""          # possibly sanitised / wrapped version
    domain: str = "general"

    # --- analysis ---
    threat_analysis: ThreatAnalysis | None = None

    # --- control flow ---
    blocked: bool = False
    block_reason: str = ""

    # --- output side ---
    response: AgentResponse | None = None
    redactions: list[str] = field(default_factory=list)

    # --- observability ---
    incidents: list[dict] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    middleware_trace: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.effective_input:
            self.effective_input = self.user_input

    def log_incident(self, content: str, meta: dict) -> None:
        """Append a timestamped incident record."""
        self.incidents.append({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "content_preview": content[:200],
            **meta,
        })


# ======================================================================
# Middleware ABC
# ======================================================================

# Type alias for the ``next`` function passed to middlewares.
NextFn = Callable[[ShieldContext], Awaitable[ShieldContext]]


class Middleware(abc.ABC):
    """Base class for all pipeline middlewares.

    Subclasses MUST implement :meth:`process`.  They SHOULD set a unique
    ``name`` class attribute used in tracing and error messages.
    """

    name: str = "unnamed"

    @abc.abstractmethod
    async def process(self, ctx: ShieldContext, next_fn: NextFn) -> ShieldContext:
        """Process *ctx* and either return early or call ``await next_fn(ctx)``
        to continue down the chain."""


# ======================================================================
# Chain runner
# ======================================================================

class MiddlewareChain:
    """Executes an ordered list of :class:`Middleware` instances as a chain.

    Each middleware receives a ``next_fn`` that, when awaited, invokes the
    next middleware.  If no middleware blocks, the terminal handler (typically
    the agent invocation) is called last.
    """

    def __init__(self, middlewares: list[Middleware] | None = None) -> None:
        self._middlewares: list[Middleware] = list(middlewares or [])

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def append(self, mw: Middleware) -> "MiddlewareChain":
        """Add *mw* to the end of the chain.  Returns self for chaining."""
        self._middlewares.append(mw)
        return self

    def prepend(self, mw: Middleware) -> "MiddlewareChain":
        """Add *mw* to the start of the chain.  Returns self for chaining."""
        self._middlewares.insert(0, mw)
        return self

    def insert_before(self, target_name: str, mw: Middleware) -> "MiddlewareChain":
        """Insert *mw* immediately before the middleware named *target_name*."""
        for i, existing in enumerate(self._middlewares):
            if existing.name == target_name:
                self._middlewares.insert(i, mw)
                return self
        raise KeyError(f"No middleware named '{target_name}' in the chain")

    def insert_after(self, target_name: str, mw: Middleware) -> "MiddlewareChain":
        """Insert *mw* immediately after the middleware named *target_name*."""
        for i, existing in enumerate(self._middlewares):
            if existing.name == target_name:
                self._middlewares.insert(i + 1, mw)
                return self
        raise KeyError(f"No middleware named '{target_name}' in the chain")

    def remove(self, name: str) -> "MiddlewareChain":
        """Remove the first middleware with the given *name*."""
        for i, existing in enumerate(self._middlewares):
            if existing.name == name:
                self._middlewares.pop(i)
                return self
        raise KeyError(f"No middleware named '{name}' in the chain")

    def replace(self, name: str, mw: Middleware) -> "MiddlewareChain":
        """Replace the middleware named *name* with *mw*."""
        for i, existing in enumerate(self._middlewares):
            if existing.name == name:
                self._middlewares[i] = mw
                return self
        raise KeyError(f"No middleware named '{name}' in the chain")

    @property
    def names(self) -> list[str]:
        """Return the ordered list of middleware names."""
        return [mw.name for mw in self._middlewares]

    def __len__(self) -> int:
        return len(self._middlewares)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def execute(self, ctx: ShieldContext) -> ShieldContext:
        """Run *ctx* through every middleware in order."""

        async def _terminal(c: ShieldContext) -> ShieldContext:
            """No-op terminal handler — reached when no middleware blocks."""
            return c

        # Build the chain from the inside out (last middleware wraps terminal).
        handler: NextFn = _terminal
        for mw in reversed(self._middlewares):
            handler = _make_next(mw, handler)

        return await handler(ctx)


def _make_next(mw: Middleware, next_fn: NextFn) -> NextFn:
    """Create a closure that calls *mw.process* with *next_fn*."""

    async def _handler(ctx: ShieldContext) -> ShieldContext:
        ctx.middleware_trace.append(mw.name)
        return await mw.process(ctx, next_fn)

    return _handler
