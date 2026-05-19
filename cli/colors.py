"""Shared CLI colour helpers."""
from __future__ import annotations

import typer

SEVERITY_COLOR: dict[str, str] = {
    "low": typer.colors.CYAN,
    "medium": typer.colors.YELLOW,
    "high": typer.colors.RED,
    "critical": typer.colors.BRIGHT_RED,
}
