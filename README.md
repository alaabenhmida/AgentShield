# AgentShield

> A standalone, pip-installable security framework for multi-agent AI systems.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![PEP 561](https://img.shields.io/badge/typing-PEP%20561-blueviolet)

---

## Install

```bash
pip install agentshield
```

For local development:

```bash
git clone https://github.com/your-org/agentshield.git
cd agentshield
pip install -e ".[dev]"
```

---

## Two Modes

AgentShield operates in two complementary modes:

| Mode | Purpose |
|------|---------|
| **Production Defence** | Wraps any multi-agent system and runs every message through 4 security layers in real time. |
| **Red-Team Simulation** | Runs 30+ attack payloads against the wrapped system and produces a scored security report. |

---

## Quick Start: Production Defence

```python
import asyncio
from agentshield import AgentShield, SystemAdapter

def my_agent(text: str) -> str:
    return f"Response to: {text}"

adapter = SystemAdapter.from_callable(my_agent, name="MyAgent")
shield = AgentShield(adapter, domain="general")

response = asyncio.run(shield.run("Hello, how are you?"))
print(response.output)
# → "Response to: <<USER_INPUT_START>>\nHello, how are you?\n<<USER_INPUT_END>>"
```

---

## Quick Start: Red Teaming

```python
import asyncio
from agentshield import SystemAdapter
from agentshield.red_team import RedTeamSimulator

def my_agent(text: str) -> str:
    return "I can only help with allowed topics."

adapter = SystemAdapter.from_callable(my_agent, name="MyAgent")
simulator = RedTeamSimulator(adapter, domains=["healthcare"], verbose=True)

report = asyncio.run(simulator.run())
RedTeamSimulator.print_report(report)
```

---

## Defence Pipeline Diagram

The pipeline is implemented as a **middleware chain** — each layer is a
`Middleware` subclass that receives a `ShieldContext` and a `next_fn`.
Layers can short-circuit (e.g. block), mutate the context, or pass through.

```
User Input
    │
    ▼
┌──────────────────────────────────────────────────────┐
│  MiddlewareChain                                     │
│                                                      │
│  ┌────────────────────────┐                          │
│  │ 1. PromptGuardMiddleware│  ← patterns, base64,    │
│  │    (prompt_guard)       │    structural, entropy   │
│  └──────────┬─────────────┘    sigmoid scoring       │
│             │ blocked → short-circuit                │
│             ▼                                        │
│  ┌────────────────────────┐                          │
│  │ 2. BoundaryMiddleware   │  ← wraps with security  │
│  │    (boundary)           │    tokens                │
│  └──────────┬─────────────┘                          │
│             ▼                                        │
│  ┌────────────────────────┐                          │
│  │ 3. [YOUR MIDDLEWARE]    │  ← insert custom layers  │
│  │    (optional)           │    anywhere in the chain │
│  └──────────┬─────────────┘                          │
│             ▼                                        │
│  ┌────────────────────────┐                          │
│  │ 4. InvokeMiddleware     │  ← calls the agent      │
│  │    (invoke)             │    system via adapter    │
│  └──────────┬─────────────┘                          │
│             ▼                                        │
│  ┌────────────────────────┐                          │
│  │ 5. OutputFilterMiddleware│ ← redacts PII, creds,  │
│  │    (output_filter)      │   structural leaks      │
│  └──────────┬─────────────┘                          │
│             ▼                                        │
│  ┌────────────────────────┐                          │
│  │ 6. InterAgentMiddleware │ ← scans inter-agent     │
│  │    (inter_agent)        │   messages (optional)   │
│  └──────────┬─────────────┘                          │
│             ▼                                        │
│  ┌─────────────────────────┐                         │
│  │ 7. ToolCallValidation   │ ← validates tool calls  │
│  │    (tool_validation)    │   (optional)            │
│  └──────────┬──────────────┘                         │
│             ▼                                        │
└──────────────────────────────────────────────────────┘
           ▼
     Sanitised Response  →  Event callbacks fired
```

---

## Middleware Pipeline

The defence pipeline is fully composable. Each layer is a `Middleware` that
can be added, removed, reordered, or replaced at runtime.

### Default chain

```python
shield = AgentShield(adapter, domain="healthcare")
print(shield.chain.names)
# ['prompt_guard', 'boundary', 'invoke', 'output_filter']
```

### Inject a custom middleware

```python
from agentshield import Middleware, ShieldContext

class RateLimiter(Middleware):
    name = "rate_limiter"

    async def process(self, ctx, next_fn):
        if self._over_limit(ctx.user_input):
            ctx.blocked = True
            ctx.block_reason = "Rate limit exceeded."
            return ctx
        return await next_fn(ctx)

shield.chain.insert_before("prompt_guard", RateLimiter())
```

### Add built-in optional middlewares

```python
from agentshield.defense.middlewares import (
    InterAgentMiddleware,
    ToolCallValidationMiddleware,
)

# Scan inter-agent messages for manipulation attempts
shield.chain.append(InterAgentMiddleware())

# Validate tool calls against an allowlist
shield.chain.append(ToolCallValidationMiddleware(
    allowed_tools=["search", "calculator", "lookup"],
))
```

### Remove or replace a layer

```python
# Skip boundary wrapping
shield.chain.remove("boundary")

# Swap the output filter for a custom one
shield.chain.replace("output_filter", MyBetterFilter())
```

### Fully custom pipeline

```python
from agentshield import AgentShield, Middleware
from agentshield.defense.middlewares import InvokeMiddleware

shield = AgentShield(
    adapter,
    middlewares=[MyAuth(), MyGuard(), InvokeMiddleware(adapter), MyLogger()],
)
```

### Writing a middleware

Every middleware receives a `ShieldContext` and a `next_fn`:

```python
from agentshield import Middleware, ShieldContext

class MyMiddleware(Middleware):
    name = "my_middleware"

    async def process(self, ctx: ShieldContext, next_fn):
        # Pre-processing: read/mutate ctx before the agent runs
        ctx.effective_input = ctx.effective_input.strip()

        # Call the next middleware (or skip to short-circuit)
        ctx = await next_fn(ctx)

        # Post-processing: inspect/mutate ctx.response
        if ctx.response:
            ctx.response.output += "\n-- powered by MyMiddleware"

        return ctx
```

| Method | Description |
|--------|-------------|
| `chain.append(mw)` | Add to end |
| `chain.prepend(mw)` | Add to start |
| `chain.insert_before(name, mw)` | Insert before a named middleware |
| `chain.insert_after(name, mw)` | Insert after a named middleware |
| `chain.remove(name)` | Remove by name |
| `chain.replace(name, mw)` | Replace by name |
| `chain.names` | List middleware names in order |

---

## Session Tracking

AgentShield tracks per-session interaction history when you pass a `session_id`:

```python
response = await shield.run("Hello", session_id="user-42")
response = await shield.run("Follow-up question", session_id="user-42")

history = shield.get_session("user-42")
# [{'timestamp': '...', 'input': 'Hello', 'output': '...', 'blocked': False, 'threat_score': 0.0}, ...]
```

---

## Event Callbacks (Webhooks)

Register callbacks for security events — useful for logging, alerting, or
webhook integrations:

```python
shield.on("before_run", lambda **kw: print(f"Processing: {kw['user_input'][:50]}"))
shield.on("after_run",  lambda **kw: log_to_dashboard(kw["response"]))
shield.on("on_block",   lambda **kw: alert_security_team(kw["reason"]))
shield.on("on_incident", lambda **kw: store_incident(kw["incident"]))
```

| Event | Keyword Args | When |
|-------|-------------|------|
| `before_run` | `user_input`, `session_id` | Before pipeline starts |
| `after_run` | `response`, `session_id` | After pipeline completes |
| `on_block` | `reason`, `user_input` | When input is blocked |
| `on_incident` | `incident` | When a security incident is logged |

---

## Configuration

### From code

```python
from agentshield import ShieldConfig
from agentshield.core.types import ThreatLevel

config = ShieldConfig(
    domain="healthcare",
    block_threshold=ThreatLevel.CRITICAL,
    enforce_boundaries=True,
    filter_output=True,
    log_incidents=True,
)
shield = AgentShield(adapter, config=config)
```

### From a JSON/YAML file

```python
from agentshield import ShieldConfig
from agentshield.core.config import load_config_dict

data = load_config_dict("config.json")   # or config.yaml (requires PyYAML)
config = ShieldConfig.from_dict(data)
shield = AgentShield(adapter, config=config)
```

### From environment variables

```bash
export AGENTSHIELD_DOMAIN=healthcare
export AGENTSHIELD_BLOCK_THRESHOLD=MALICIOUS
export AGENTSHIELD_ENFORCE_BOUNDARIES=true
export AGENTSHIELD_FILTER_OUTPUT=true
```

```python
data = load_config_dict()  # reads AGENTSHIELD_* env vars automatically
config = ShieldConfig.from_dict(data)
```

---

## Logging

AgentShield uses Python's standard `logging` module. Configure it to see
security events:

```python
import logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("agentshield").setLevel(logging.DEBUG)
```

Logger names: `agentshield.shield`, `agentshield.prompt_guard`,
`agentshield.output_filter`, `agentshield.rag_shield`, `agentshield.middlewares`.

---

## Adapter Protocol

In addition to the `SystemAdapter` ABC, AgentShield exports a
`SystemAdapterProtocol` (PEP 544 runtime-checkable protocol). Any object
with `invoke()` and `get_system_info()` methods satisfies the protocol —
no inheritance required:

```python
from agentshield import SystemAdapterProtocol

class MyAdapter:
    async def invoke(self, user_input: str) -> AgentResponse:
        return AgentResponse(output="Hello")

    def get_system_info(self) -> dict:
        return {"framework": "Custom"}

assert isinstance(MyAdapter(), SystemAdapterProtocol)  # ✓
```

---

## Sigmoid Scoring

The prompt-injection guard uses a **sigmoid normalisation** curve instead
of a simple linear clamp. This gives more interpretable scores and avoids
inflation when multiple weak signals fire together:

```
score = 1 / (1 + e^(-k × (raw - midpoint)))
```

- `midpoint = 0.65` — raw score that maps to ~0.5
- `steepness = 8.0` — how sharply the curve transitions

---

## Supported Frameworks

| Framework | Adapter Factory | Install Extra |
|-----------|----------------|---------------|
| LangGraph | `SystemAdapter.for_langgraph(graph)` | `pip install agentshield[langgraph]` |
| CrewAI | `SystemAdapter.for_crewai(crew)` | `pip install agentshield[crewai]` |
| LangChain | `SystemAdapter.for_langchain(agent)` | `pip install agentshield[langchain]` |
| Any callable | `SystemAdapter.from_callable(fn)` | — (no extras) |

---

## Domain Plugins

| Domain | What It Adds | Factory Function |
|--------|-------------|-----------------|
| Healthcare | Medical keywords, patient ID / NPI / ICD-10 redactions, trusted medical domains | `create_healthcare_shield()` |
| Finance | Financial keywords, SWIFT / routing number / IBAN redactions, trusted finance domains | `create_finance_shield()` |
| Legal | Legal keywords, case number / bar number redactions, trusted legal domains | `create_legal_shield()` |

---

## Built-in Middlewares

| Middleware | Name | Default? | Purpose |
|-----------|------|----------|---------|
| `PromptGuardMiddleware` | `prompt_guard` | Yes | 4-layer async threat analysis |
| `BoundaryMiddleware` | `boundary` | Yes | Security token wrapping |
| `InvokeMiddleware` | `invoke` | Yes | Agent system invocation |
| `OutputFilterMiddleware` | `output_filter` | Yes | PII / credential redaction |
| `InterAgentMiddleware` | `inter_agent` | No | Scans inter-agent messages |
| `ToolCallValidationMiddleware` | `tool_validation` | No | Tool allowlist + danger patterns |

---

## How to Extend

### Add a new attack

```python
from agentshield.red_team.attack_library import Attack, UNIVERSAL_ATTACKS
from agentshield.core.types import AttackCategory

UNIVERSAL_ATTACKS.append(Attack(
    attack_id="CUSTOM-001",
    category=AttackCategory.PROMPT_INJECTION,
    payload="Your custom attack payload here.",
    success_indicators=["leaked", "secret"],
    failure_indicators=["can't", "blocked"],
))
```

### Add a new detection pattern

```python
from agentshield.defense.prompt_guard import UNIVERSAL_PATTERNS
import re

UNIVERSAL_PATTERNS.append(
    (re.compile(r"my_custom_evil_pattern", re.IGNORECASE), "custom_label", 0.85)
)
```

### Add a new adapter

```python
from agentshield.core.adapter import SystemAdapter
from agentshield.core.types import AgentResponse

class MyFrameworkAdapter(SystemAdapter):
    def __init__(self, client):
        self._client = client

    async def invoke(self, user_input: str) -> AgentResponse:
        result = await self._client.run(user_input)
        return AgentResponse(output=str(result))

    def get_system_info(self) -> dict:
        return {"framework": "MyFramework"}
```

### Add a new domain

```python
from agentshield.defense.prompt_guard import DOMAIN_KEYWORDS
from agentshield.defense.output_filter import DOMAIN_REDACTIONS

DOMAIN_KEYWORDS["my_domain"] = ["keyword1", "keyword2"]
DOMAIN_REDACTIONS["my_domain"] = [
    (r"\bPATTERN\b", "[MY_REDACTED]"),
]
```

### Add a custom middleware

```python
from agentshield import Middleware, ShieldContext
from agentshield.core.types import AgentResponse

class AuditLogger(Middleware):
    name = "audit_logger"

    async def process(self, ctx: ShieldContext, next_fn):
        print(f"[AUDIT] Input: {ctx.user_input[:50]}")
        ctx = await next_fn(ctx)
        if ctx.response:
            print(f"[AUDIT] Output: {ctx.response.output[:50]}")
        return ctx

# Insert into any shield's pipeline:
shield.chain.insert_after("prompt_guard", AuditLogger())
```

---

## Project Structure

```
agentshield/
├── __init__.py                  # Public API exports
├── py.typed                     # PEP 561 typing marker
├── core/
│   ├── __init__.py              # Re-exports core types, adapter, shield, middleware, config
│   ├── types.py                 # Dataclasses and enums (zero internal imports)
│   ├── adapter.py               # SystemAdapter ABC + Protocol + framework adapters
│   ├── config.py                # Config loader (JSON / YAML / env vars)
│   ├── middleware.py            # Middleware ABC, ShieldContext, MiddlewareChain runner
│   └── shield.py                # AgentShield orchestrator (sessions, webhooks, logging)
├── defense/
│   ├── __init__.py              # Exports all defence modules + built-in middlewares
│   ├── prompt_guard.py          # 4-layer async prompt-injection detector (sigmoid scored)
│   ├── boundary.py              # Security token wrapper + system prefix
│   ├── rag_shield.py            # RAG document scanner + integrity checker
│   ├── output_filter.py         # PII / credential / leak redaction
│   └── middlewares.py           # Built-in middlewares (6 total incl. inter-agent & tool validation)
├── red_team/
│   ├── __init__.py              # Exports attack library + simulator
│   ├── attack_library.py        # 30+ curated attack payloads
│   └── simulator.py             # Automated red-team engine + report printer
├── domains/
│   ├── __init__.py              # Domain plugin exports
│   ├── healthcare.py            # Healthcare keywords, redactions, trusted domains
│   ├── finance.py               # Finance keywords, redactions, trusted domains
│   └── legal.py                 # Legal keywords, redactions, trusted domains
├── tests/
│   ├── __init__.py
│   ├── test_prompt_guard.py     # Pattern matching, structural, and scoring tests
│   ├── test_adapters.py         # Callable adapter tests (sync, async, error)
│   ├── test_simulator.py        # End-to-end simulator tests
│   ├── test_middleware.py       # Middleware chain, mutation, and integration tests
│   ├── test_rag_shield.py       # RAG document scanning, integrity, injection tests
│   ├── test_boundary.py         # Boundary wrapping / unwrapping tests
│   ├── test_output_filter.py    # PII redaction, domain redactions, leak tests
│   └── test_features.py         # Config, sessions, webhooks, protocol, new middleware tests
├── pyproject.toml               # Build config, extras, pytest settings
└── README.md                    # This file
```

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest agentshield/tests/ -v
```

All tests use mock callables — no API keys, no network calls.

---

## License

MIT
