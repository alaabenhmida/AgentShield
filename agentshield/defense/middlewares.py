"""Built-in middleware implementations wrapping the four defence layers.

These are the default middlewares that :class:`AgentShield` assembles into
its pipeline.  Users can replace, reorder, or extend them freely.
"""

from __future__ import annotations

import logging
import re

from agentshield.core.middleware import Middleware, ShieldContext, NextFn
from agentshield.core.types import AgentResponse

log = logging.getLogger("agentshield.middlewares")


# ======================================================================
# Layer 1 — Prompt-injection guard
# ======================================================================

class PromptGuardMiddleware(Middleware):
    """Analyses user input for injection patterns, jailbreaks, and anomalies.

    If the threat level meets or exceeds the block threshold the context is
    marked as blocked and downstream middlewares are skipped.
    """

    name = "prompt_guard"

    def __init__(self, domain: str = "general") -> None:
        from agentshield.defense.prompt_guard import PromptInjectionGuard
        self._guard = PromptInjectionGuard(domain=domain)

    async def process(self, ctx: ShieldContext, next_fn: NextFn) -> ShieldContext:
        analysis = await self._guard.analyze(ctx.user_input)
        ctx.threat_analysis = analysis

        if analysis.is_blocked:
            ctx.blocked = True
            ctx.block_reason = (
                f"Blocked: threat_level={analysis.threat_level.value}, "
                f"score={analysis.score:.2f}, "
                f"matched_patterns={analysis.matched_patterns}"
            )
            ctx.log_incident(ctx.user_input, {
                "stage": "prompt_guard",
                "threat_level": analysis.threat_level.value,
                "score": analysis.score,
                "matched_patterns": analysis.matched_patterns,
            })
            ctx.response = AgentResponse(
                output=(
                    "I'm sorry, but I cannot process this request. "
                    "It has been flagged for security reasons."
                ),
                error=ctx.block_reason,
            )
            return ctx  # short-circuit

        # Use sanitised input if available
        if analysis.sanitized_input:
            ctx.effective_input = analysis.sanitized_input

        # Log elevated-score incidents (even if not blocked)
        if analysis.score > 0.3:
            ctx.log_incident(ctx.user_input, {
                "stage": "elevated_score",
                "threat_level": analysis.threat_level.value,
                "score": analysis.score,
                "matched_patterns": analysis.matched_patterns,
                "structural_flags": analysis.structural_flags,
                "anomaly_flags": analysis.anomaly_flags,
            })

        return await next_fn(ctx)


# ======================================================================
# Layer 2 — Boundary enforcement
# ======================================================================

class BoundaryMiddleware(Middleware):
    """Wraps the effective input in security tokens."""

    name = "boundary"

    def __init__(self) -> None:
        from agentshield.defense.boundary import BoundaryEnforcer
        self._enforcer = BoundaryEnforcer()

    async def process(self, ctx: ShieldContext, next_fn: NextFn) -> ShieldContext:
        ctx.effective_input = self._enforcer.wrap(ctx.effective_input)
        return await next_fn(ctx)


# ======================================================================
# Layer 3 — Agent invocation
# ======================================================================

class InvokeMiddleware(Middleware):
    """Calls the wrapped agent/system adapter.

    This middleware is the bridge between the pre-processing layers and
    the post-processing layers.  It reads ``ctx.effective_input`` and
    writes ``ctx.response``.
    """

    name = "invoke"

    def __init__(self, adapter: object) -> None:
        self._adapter = adapter

    async def process(self, ctx: ShieldContext, next_fn: NextFn) -> ShieldContext:
        ctx.response = await self._adapter.invoke(ctx.effective_input)  # type: ignore[union-attr]
        return await next_fn(ctx)


# ======================================================================
# Layer 4 — Output filtering
# ======================================================================

class OutputFilterMiddleware(Middleware):
    """Scans the agent response for PII, credentials, and structural leaks."""

    name = "output_filter"

    def __init__(self, domain: str = "general") -> None:
        from agentshield.defense.output_filter import OutputFilter
        self._filter = OutputFilter(domain=domain)

    async def process(self, ctx: ShieldContext, next_fn: NextFn) -> ShieldContext:
        if ctx.response and ctx.response.output:
            filtered = self._filter.scan(ctx.response.output)
            ctx.response.output = filtered.text
            ctx.redactions = filtered.redactions
            if filtered.had_leaks:
                ctx.log_incident(ctx.response.output, {
                    "stage": "output_filter",
                    "redactions": filtered.redactions,
                })
        return await next_fn(ctx)


# ======================================================================
# Layer 5 (optional) — Inter-agent message scanning
# ======================================================================

# Pre-compiled patterns for inter-agent manipulation attempts
_AGENT_MSG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE), "agent_msg_override"),
    (re.compile(r"\[SYSTEM\]|\[ADMIN\]", re.IGNORECASE), "agent_msg_fake_tag"),
    (re.compile(r"(reveal|show|print)\s+(your\s+)?system\s+prompt", re.IGNORECASE), "agent_msg_prompt_leak"),
    (re.compile(r"you\s+are\s+now", re.IGNORECASE), "agent_msg_persona_override"),
    (re.compile(r"transfer\s+all|send\s+all|forward\s+all", re.IGNORECASE), "agent_msg_data_exfil"),
]


class InterAgentMiddleware(Middleware):
    """Scans inter-agent messages in the response for manipulation attempts.

    Checks ``AgentResponse.intermediate_steps`` for patterns that indicate
    one agent tried to inject instructions into another.
    """

    name = "inter_agent"

    async def process(self, ctx: ShieldContext, next_fn: NextFn) -> ShieldContext:
        # Run downstream first so we have a response with intermediate_steps
        ctx = await next_fn(ctx)

        if ctx.response is None:
            return ctx

        steps = ctx.response.intermediate_steps
        if not steps:
            return ctx

        for i, step in enumerate(steps):
            lowered = step.lower()
            for compiled, label in _AGENT_MSG_PATTERNS:
                if compiled.search(lowered):
                    ctx.log_incident(step, {
                        "stage": "inter_agent",
                        "step_index": i,
                        "flag": label,
                    })
                    log.warning("Inter-agent flag '%s' in step %d", label, i)

        return ctx


# ======================================================================
# Layer 6 (optional) — Tool-call validation
# ======================================================================

# Default set of dangerous tool-call indicators
_TOOL_DANGER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE)\s+", re.IGNORECASE), "sql_injection"),
    (re.compile(r"os\.(system|popen|exec)", re.IGNORECASE), "os_command"),
    (re.compile(r"subprocess\.(run|Popen|call)", re.IGNORECASE), "subprocess_exec"),
    (re.compile(r"eval\(|exec\(", re.IGNORECASE), "code_eval"),
    (re.compile(r"__import__\(", re.IGNORECASE), "dynamic_import"),
    (re.compile(r"rm\s+-rf|del\s+/[fqs]", re.IGNORECASE), "destructive_cmd"),
]


class ToolCallValidationMiddleware(Middleware):
    """Validates tool calls in the response for dangerous patterns.

    Inspects ``AgentResponse.tools_called`` and the raw response for SQL
    injection, OS command execution, and other risky operations.

    Parameters
    ----------
    allowed_tools:
        Allowlist of tool names.  If set, any tool not on the list is flagged.
    """

    name = "tool_validation"

    def __init__(self, allowed_tools: list[str] | None = None) -> None:
        self._allowed = set(allowed_tools) if allowed_tools else None

    async def process(self, ctx: ShieldContext, next_fn: NextFn) -> ShieldContext:
        ctx = await next_fn(ctx)

        if ctx.response is None:
            return ctx

        # Check tool allowlist
        if self._allowed and ctx.response.tools_called:
            for tool in ctx.response.tools_called:
                if tool not in self._allowed:
                    ctx.log_incident(tool, {
                        "stage": "tool_validation",
                        "flag": "unauthorised_tool",
                        "tool": tool,
                    })
                    log.warning("Unauthorised tool call: %s", tool)

        # Scan input for dangerous tool-call payloads
        for compiled, label in _TOOL_DANGER_PATTERNS:
            if compiled.search(ctx.effective_input):
                ctx.log_incident(ctx.effective_input, {
                    "stage": "tool_validation",
                    "flag": label,
                })
                log.warning("Tool-call danger pattern '%s' in input", label)

        return ctx
