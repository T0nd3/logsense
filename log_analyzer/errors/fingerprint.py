from __future__ import annotations

import hashlib
import re

from .normalizer import normalize

# Patterns that indicate a named exception/error type at the start of a message
_EXCEPTION_PREFIX = re.compile(
    r'^(?:[\w.]+\.)?'           # optional package prefix (java.lang.)
    r'(\w*(?:Exception|Error|Fault|Failure|Warning|Panic|Abort))'
    r'\b',
    re.IGNORECASE,
)

# "ERROR Failed to …" / "CRITICAL Database down"
_SEVERITY_PREFIX = re.compile(
    r'^(?:ERROR|CRITICAL|FATAL|WARN(?:ING)?)\s+',
    re.IGNORECASE,
)


def extract_error_type(message: str) -> str:
    """Best-effort extraction of a stable error class name from a log message."""
    # Strip leading severity word
    msg = _SEVERITY_PREFIX.sub("", message).strip()

    m = _EXCEPTION_PREFIX.match(msg)
    if m:
        return m.group(1)

    # "SomeError: details…"  or  "ConnectionError: …"
    colon_idx = msg.find(":")
    if 0 < colon_idx < 60:
        candidate = msg[:colon_idx].strip()
        if re.match(r'^[\w.]+$', candidate):
            # Take the last component: "java.lang.NullPointerException" → "NullPointerException"
            return candidate.split(".")[-1]

    # Fallback: first three words (gives some grouping without being too specific)
    words = msg.split()
    return " ".join(words[:3]) if words else "UnknownError"


def fingerprint(message: str) -> str:
    """Return a 12-char hex fingerprint for a log message.

    Two messages with the same error class and normalized form produce the
    same fingerprint even if they differ in addresses, numbers, or hostnames.
    """
    error_type = extract_error_type(message)
    normalized_msg = normalize(message)
    key = f"{error_type}:{normalized_msg}"
    return hashlib.sha1(key.encode()).hexdigest()[:12]
