"""Normalize log messages to produce stable fingerprints.

The goal: two messages that describe the same error class produce the same
normalized form even if they differ in hostnames, numbers, UUIDs, timestamps,
or file paths.

  "ConnectionError: Failed to connect to db-prod-3.internal:5432 after 30s"
  "ConnectionError: Failed to connect to db-prod-4.internal:5432 after 60s"
  → "ConnectionError: Failed to connect to <HOST>:<PORT> after <NUM>s"
"""
from __future__ import annotations

import re

# Substitutions applied in order — ORDER MATTERS (specific before general)
_STEPS: list[tuple[re.Pattern, str]] = [
    # UUIDs (before generic hex)
    (re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        re.IGNORECASE,
    ), "<UUID>"),

    # ISO timestamps (before generic numbers)
    (re.compile(
        r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'
    ), "<TIMESTAMP>"),

    # Unix epoch timestamps (10-13 digit standalone numbers)
    (re.compile(r'\b1[0-9]{9,12}\b'), "<TIMESTAMP>"),

    # Stack-frame line numbers: "line 42" or ":42)"
    (re.compile(r'(?<=:)\d+(?=[,\)]|$)'), "<NUM>"),
    (re.compile(r'\bline \d+\b', re.IGNORECASE), "line <NUM>"),

    # File paths (Unix + Windows) — before generic numbers
    (re.compile(r'[A-Za-z]:\\(?:[\w .\-]+\\)*[\w .\-]+'), "<PATH>"),
    (re.compile(r'(?<!\w)/(?:[\w.\-]+/)*[\w.\-]+'), "<PATH>"),

    # Hex memory addresses: 0x7f3a1b2c
    (re.compile(r'\b0x[0-9a-fA-F]+\b'), "<ADDR>"),

    # Infrastructure hostnames: words with digits and dots/hyphens that look like FQDNs
    # e.g. db-prod-3.internal, redis-01.svc.cluster.local
    (re.compile(
        r'\b[a-z][a-z0-9\-]*\d[a-z0-9\-]*(?:\.[a-z][a-z0-9\-]*)+\b'
    ), "<HOST>"),

    # Port numbers in connection strings: :5432  :443
    (re.compile(r'(?<=:)\d{2,5}\b'), "<PORT>"),

    # Generic integers and floats (after all specific patterns)
    (re.compile(r'\b\d+(?:\.\d+)?\b'), "<NUM>"),
]

# Collapse repeated whitespace and strip
_WHITESPACE = re.compile(r'\s+')


def normalize(message: str) -> str:
    result = message
    for pattern, replacement in _STEPS:
        result = pattern.sub(replacement, result)
    return _WHITESPACE.sub(" ", result).strip()
