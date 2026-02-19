"""Red-team module — attack library and automated simulation."""

from __future__ import annotations

from agentshield.red_team.attack_library import (
    Attack,
    get_attacks,
    UNIVERSAL_ATTACKS,
    DOMAIN_ATTACK_MAP,
)
from agentshield.red_team.simulator import RedTeamSimulator

__all__ = [
    "Attack",
    "get_attacks",
    "UNIVERSAL_ATTACKS",
    "DOMAIN_ATTACK_MAP",
    "RedTeamSimulator",
]
