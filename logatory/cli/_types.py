"""Shared CLI type helpers."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from enum import Enum

import typer

from logatory.pii.redactor import RedactMode


class RedactModeArg(str, Enum):
    redact = "redact"
    mask = "mask"
    dry_run = "dry-run"


REDACT_MAP: dict[RedactModeArg, RedactMode] = {
    RedactModeArg.redact: RedactMode.REDACT,
    RedactModeArg.mask: RedactMode.MASK,
    RedactModeArg.dry_run: RedactMode.DRY_RUN,
}


# ---------------------------------------------------------------------------
# Relative time-spec parser used by --since options across the adapter CLIs.
# ---------------------------------------------------------------------------

_LOOKBACK_RE = re.compile(r"^(\d+)([smhd])$")
_UNIT_SECONDS: dict[str, int] = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_lookback_seconds(spec: str) -> int:
    """Parse a relative time spec ('30s', '5m', '1h', '7d') into seconds.

    Raises ``typer.BadParameter`` on invalid input so the user sees a
    formatted CLI error instead of a stack trace.
    """
    m = _LOOKBACK_RE.match(spec.strip())
    if not m:
        raise typer.BadParameter(f"Invalid time spec '{spec}'. Use e.g. 30s, 5m, 1h, 7d.")
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)]


def parse_lookback_utc(spec: str) -> datetime:
    """Return the absolute UTC datetime that is *spec* ago from now.

    Convenience wrapper for adapters that need a datetime cursor rather
    than a duration.  Raises ``typer.BadParameter`` on invalid input.
    """
    return datetime.now(tz=UTC) - timedelta(seconds=parse_lookback_seconds(spec))
