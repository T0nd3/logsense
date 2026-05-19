from __future__ import annotations

import re
from datetime import datetime

from ..models import Event, Severity
from .base import BaseParser

# Nginx/Apache Combined Log Format
_COMBINED_RE = re.compile(
    r'(?P<remote_addr>\S+) '
    r'(?P<ident>\S+) '
    r'(?P<auth>\S+) '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) '
    r'(?P<bytes>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _status_to_severity(status: int) -> Severity:
    if status >= 500:
        return Severity.ERROR
    if status >= 400:
        return Severity.WARNING
    return Severity.INFO


class NginxCombinedParser(BaseParser):
    def parse(self, line: str) -> Event | None:
        stripped = line.strip()
        if not stripped:
            return None
        m = _COMBINED_RE.match(stripped)
        if not m:
            return None

        fields = m.groupdict()
        status = int(fields["status"])
        timestamp = None
        try:
            timestamp = datetime.strptime(fields["time"], _TIME_FMT)
        except ValueError:
            pass

        message = f'{fields["request"]} -> {status}'

        return Event(
            raw=stripped,
            source=self.source,
            message=message,
            timestamp=timestamp,
            severity=_status_to_severity(status),
            parsed_fields={
                "remote_addr": fields["remote_addr"],
                "request": fields["request"],
                "status": status,
                "bytes": fields["bytes"],
                "referer": fields.get("referer") or "",
                "user_agent": fields.get("user_agent") or "",
            },
        )
