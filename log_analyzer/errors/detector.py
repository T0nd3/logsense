"""Error event detection and stack trace extraction."""

from __future__ import annotations

import re

from ..models import Event, Severity

# Severity levels that qualify as errors
_ERROR_SEVERITIES = {Severity.ERROR, Severity.CRITICAL}

# Message patterns that indicate an error even at INFO/WARNING severity
_ERROR_PATTERNS = [
    re.compile(r"\b(?:Exception|Traceback|StackTrace|NullPointer)\b", re.IGNORECASE),
    re.compile(r"\b(?:FATAL|CRITICAL|PANIC|ABORT)\b"),
    re.compile(r"(?:^|\s)(?:Error|Err):\s", re.IGNORECASE),
]


# HTTP 5xx in parsed_fields
def _is_http_error(event: Event) -> bool:
    status = event.parsed_fields.get("status")
    if status is not None:
        try:
            return int(status) >= 500
        except (ValueError, TypeError):
            pass
    return False


def is_error_event(event: Event) -> bool:
    if event.severity in _ERROR_SEVERITIES:
        return True
    if _is_http_error(event):
        return True
    return any(p.search(event.message) for p in _ERROR_PATTERNS)


# ---------------------------------------------------------------------------
# Stack trace detection
# ---------------------------------------------------------------------------

# Start markers for each language
_STACK_STARTS = [
    re.compile(r"^Traceback \(most recent call last\)", re.MULTILINE),  # Python
    re.compile(r"^\s+at [\w.$<>]+\([\w.]+:\d+\)", re.MULTILINE),  # Java/Kotlin
    re.compile(r"^\s+at [\w.<>]+\s+\([\w./:\\]+:\d+:\d+\)", re.MULTILINE),  # JS/TS
    re.compile(r"^\s+at \w[\w.+`]+ in .+:\d+", re.MULTILINE),  # .NET/C#
]

# Frame line patterns per language
_FRAME_PATTERNS = [
    re.compile(r'^\s+File ".+", line \d+, in .+'),  # Python frame
    re.compile(r"^\s+at [\w.$<>]+\([\w.]+(?::\d+)?\)"),  # Java frame
    re.compile(r"^\s+at .+\(.+:\d+:\d+\)"),  # JS/TS frame
    re.compile(r"^\s+at .+ in .+:\d+"),  # .NET frame
]


def detect_stack_trace(message: str) -> str | None:
    """Return extracted stack trace text if the message contains one, else None."""
    for pattern in _STACK_STARTS:
        if pattern.search(message):
            return message
    # Single-line that looks like a frame
    for pattern in _FRAME_PATTERNS:
        if pattern.match(message):
            return message
    return None


def classify_stack_language(stack: str) -> str:
    """Best-effort language classification of a stack trace."""
    if "Traceback (most recent call last)" in stack or 'File "' in stack:
        return "python"
    if re.search(r"at [\w.$]+\([\w]+\.java:\d+\)", stack):
        return "java"
    if re.search(r"at .+\(.+\.(?:js|ts|mjs):\d+", stack):
        return "javascript"
    if re.search(r"at .+ in .+\.cs:\d+", stack):
        return "dotnet"
    return "unknown"
