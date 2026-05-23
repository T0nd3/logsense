"""Rule engine package — Sigma + native YAML detection rules."""

from __future__ import annotations

from pathlib import Path

# Directory holding the shipped built-in detection rules.  Single source
# of truth for every command / web entrypoint that boots the engine.
BUILTIN_RULES_DIR: Path = Path(__file__).parent / "builtin"

__all__ = ["BUILTIN_RULES_DIR"]
