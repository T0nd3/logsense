"""Loads a targets.yaml so the dashboard can offer a fleet target filter.

The targets file is looked up relative to the working directory the
dashboard was started in — the same default the `fleet` CLI uses. When no
valid file is present the helpers return empty results and the dashboard
simply omits the target filter.
"""

from __future__ import annotations

from pathlib import Path

from logatory.fleet import load_targets

_TARGETS_FILE = Path("targets.yaml")


def _load(path: Path) -> list:
    try:
        return load_targets(path)
    except Exception:
        return []


def fleet_options(path: Path = _TARGETS_FILE) -> list[dict]:
    """Dropdown options for the dashboard target filter.

    One entry per configured target, then one per group. Empty when no valid
    targets file is present.
    """
    targets = _load(path)
    if not targets:
        return []
    options = [{"value": f"t:{t.name}", "label": t.name} for t in targets]
    groups = sorted({g for t in targets for g in t.groups})
    options += [{"value": f"g:{g}", "label": f"{g} (group)"} for g in groups]
    return options


def resolve_filter(selection: str | None, path: Path = _TARGETS_FILE) -> list[str] | None:
    """Resolve a dropdown selection to a list of target names, or None for 'all'.

    A ``t:<name>`` value resolves to that one target; a ``g:<group>`` value
    resolves to every target in the group.
    """
    if not selection:
        return None
    targets = _load(path)
    if selection.startswith("g:"):
        members = [t.name for t in targets if selection[2:] in t.groups]
        return members or None
    if selection.startswith("t:"):
        name = selection[2:]
        return [name] if any(t.name == name for t in targets) else None
    return None
