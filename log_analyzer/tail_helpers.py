"""Helpers for the realtime tail pipeline.

Kept in the library layer (no typer dependency) so they can be
tested and reused without the CLI.
"""

from __future__ import annotations

import json
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from log_analyzer.models import Finding

_SEV_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def meets_alert_severity(finding: Finding, min_severity: str) -> bool:
    """Return True if finding.severity >= min_severity."""
    return _SEV_ORDER.get(finding.severity.value, 0) >= _SEV_ORDER.get(min_severity.lower(), 2)


def post_webhook(url: str, finding: Finding) -> None:
    """POST a finding as JSON to a webhook URL.

    Failures are silently swallowed — the tail loop must never stop
    because a webhook is unavailable.
    """
    payload = {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "message": finding.message,
        "source": finding.source,
        "timestamp": finding.timestamp.isoformat(),
    }
    data = json.dumps(payload).encode()
    try:
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass
