"""Raw read/write of targets.yaml for the dashboard config editor.

Unlike ``logatory.fleet.load_targets``, this does NOT interpolate
``${ENV_VAR}`` references — so credentials stay as references when the file
is read back and rewritten by the editor.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_TARGETS_FILE = Path("targets.yaml")


def read_targets(path: Path = _TARGETS_FILE) -> list[dict]:
    """Return the raw target dicts from a targets file (no env interpolation)."""
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return []
    targets = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(targets, list):
        return []
    return [t for t in targets if isinstance(t, dict)]


def write_targets(targets: list[dict], path: Path = _TARGETS_FILE) -> None:
    """Write a list of raw target dicts back to a targets file."""
    path.write_text(
        yaml.safe_dump({"targets": targets}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
