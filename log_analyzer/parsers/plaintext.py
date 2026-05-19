from __future__ import annotations

from ..models import Event, Severity
from .base import BaseParser

_ERROR_WORDS = frozenset(("error", "err", "fatal", "critical", "exception", "traceback"))
_WARN_WORDS = frozenset(("warn", "warning", "deprecated"))


def _infer_severity(line: str) -> Severity:
    lower = line.lower()
    if any(w in lower for w in _ERROR_WORDS):
        return Severity.ERROR
    if any(w in lower for w in _WARN_WORDS):
        return Severity.WARNING
    return Severity.INFO


class PlaintextParser(BaseParser):
    def parse(self, line: str) -> Event | None:
        stripped = line.strip()
        if not stripped:
            return None
        return Event(
            raw=stripped,
            source=self.source,
            message=stripped,
            timestamp=None,
            severity=_infer_severity(stripped),
        )
