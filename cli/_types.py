"""Shared CLI type helpers."""
from __future__ import annotations

from enum import Enum

from log_analyzer.pii.redactor import RedactMode


class RedactModeArg(str, Enum):
    redact = "redact"
    mask = "mask"
    dry_run = "dry-run"


REDACT_MAP: dict[RedactModeArg, RedactMode] = {
    RedactModeArg.redact: RedactMode.REDACT,
    RedactModeArg.mask: RedactMode.MASK,
    RedactModeArg.dry_run: RedactMode.DRY_RUN,
}
