from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from ..models import Event
from ..storage.errors_repo import ErrorsRepository
from .detector import classify_stack_language, detect_stack_trace, is_error_event
from .fingerprint import extract_error_type, fingerprint
from .normalizer import normalize


class ErrorTracker:
    """Detects error events, deduplicates them by fingerprint, and persists to SQLite."""

    def __init__(self, repo: ErrorsRepository) -> None:
        self._repo = repo

    def process(self, event: Event) -> sqlite3.Row | None:
        """Process one event. Returns the updated ErrorRecord row if it's an error, else None."""
        if not is_error_event(event):
            return None

        msg = event.message
        fp = fingerprint(msg)
        error_type = extract_error_type(msg)
        normalized_msg = normalize(msg)
        ts = event.timestamp or datetime.now(tz=UTC)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)

        stack = detect_stack_trace(msg)
        stack_lang = classify_stack_language(stack) if stack else None

        return self._repo.upsert(
            fingerprint=fp,
            error_type=error_type,
            normalized_msg=normalized_msg,
            severity=event.severity.value,
            source=event.source,
            timestamp=ts,
            sample=msg[:500],
            stack_trace=stack,
            stack_lang=stack_lang,
        )
