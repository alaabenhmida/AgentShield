"""Configuration helpers — load ShieldConfig from files or environment variables."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def load_config_dict(path: str | Path | None = None) -> dict[str, Any]:
    """Load a configuration dictionary from a file or environment variables.

    Resolution order
    ~~~~~~~~~~~~~~~~
    1. If *path* is given explicitly, load from that file (JSON or YAML).
    2. Otherwise check the ``AGENTSHIELD_CONFIG`` environment variable.
    3. Fall back to an empty dict (= all defaults).

    YAML support requires ``PyYAML`` to be installed; JSON works with stdlib.
    """
    if path is None:
        path = os.environ.get("AGENTSHIELD_CONFIG")

    if path is None:
        return _from_env()

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")

    text = p.read_text(encoding="utf-8")

    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required to load YAML config files.  "
                "Install it with: pip install pyyaml"
            ) from exc
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)

    return data


def _from_env() -> dict[str, Any]:
    """Build a config dict from ``AGENTSHIELD_*`` environment variables."""
    data: dict[str, Any] = {}

    if val := os.environ.get("AGENTSHIELD_DOMAIN"):
        data["domain"] = val
    if val := os.environ.get("AGENTSHIELD_BLOCK_THRESHOLD"):
        data["block_threshold"] = val
    if val := os.environ.get("AGENTSHIELD_ENFORCE_BOUNDARIES"):
        data["enforce_boundaries"] = val.lower() in ("1", "true", "yes")
    if val := os.environ.get("AGENTSHIELD_FILTER_OUTPUT"):
        data["filter_output"] = val.lower() in ("1", "true", "yes")
    if val := os.environ.get("AGENTSHIELD_LOG_INCIDENTS"):
        data["log_incidents"] = val.lower() in ("1", "true", "yes")

    return data
