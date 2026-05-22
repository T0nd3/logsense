"""Graylog source adapter — reads logs from a Graylog server over HTTP.

Queries Graylog's universal search REST API. No extra dependency — uses the
standard library HTTP client. Read-only: an access token or a viewer
account is enough.

Graylog stores structured messages (timestamp, source, level, fields), so
each message is mapped to an Event directly — no format detection needed.
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from ..models import Event, Severity
from ._http import basic_auth_header, http_get
from .base import SourceAdapter

_RELATIVE = "/api/search/universal/relative"
_ABSOLUTE = "/api/search/universal/absolute"
_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Graylog stores the syslog level (0 emerg … 7 debug) in the `level` field.
_LEVEL_MAP = {
    0: Severity.CRITICAL,
    1: Severity.CRITICAL,
    2: Severity.CRITICAL,
    3: Severity.ERROR,
    4: Severity.WARNING,
    5: Severity.INFO,
    6: Severity.INFO,
    7: Severity.DEBUG,
}


def _parse_ts(raw) -> datetime | None:
    if not raw:
        return None
    text = str(raw).replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    try:
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def _map_message(msg: dict) -> Event | None:
    """Map one Graylog message document to an Event."""
    text = msg.get("message")
    if text is None:
        return None
    message = str(text)

    severity = Severity.INFO
    level = msg.get("level")
    if level is not None:
        try:
            severity = _LEVEL_MAP.get(int(level), Severity.INFO)
        except (ValueError, TypeError):
            pass

    timestamp = _parse_ts(msg.get("timestamp"))
    source = str(msg.get("source") or "graylog")

    parsed = {
        k: v for k, v in msg.items() if k != "message" and isinstance(v, (str, int, float, bool))
    }

    return Event(
        raw=message,
        source=source,
        message=message,
        timestamp=timestamp,
        severity=severity,
        parsed_fields=parsed,
    )


class GraylogAdapter(SourceAdapter):
    """Reads log events from a Graylog server via its universal search API."""

    def __init__(
        self,
        *,
        url: str = "http://localhost:9000",
        query: str = "*",
        range_seconds: int = 3600,
        limit: int = 1000,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        timeout: float = 30.0,
        fetcher=None,
    ) -> None:
        self._url = url.rstrip("/")
        self._query = query
        self._range_seconds = range_seconds
        self._limit = limit
        self._username = username
        self._password = password
        self._token = token
        self._timeout = timeout
        self._fetcher = fetcher  # injectable for tests: (url, headers) -> str

    # -- request construction ----------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "X-Requested-By": "logatory"}
        if self._token:
            # a Graylog access token authenticates as <token>:token
            headers["Authorization"] = basic_auth_header(self._token, "token")
        elif self._username and self._password:
            headers["Authorization"] = basic_auth_header(self._username, self._password)
        return headers

    def _relative_url(self) -> str:
        params = urllib.parse.urlencode(
            {
                "query": self._query,
                "range": str(self._range_seconds),
                "limit": str(self._limit),
                "sort": "timestamp:asc",
            }
        )
        return f"{self._url}{_RELATIVE}?{params}"

    def _absolute_url(self, since: datetime) -> str:
        params = urllib.parse.urlencode(
            {
                "query": self._query,
                "from": since.astimezone(UTC).strftime(_TS_FORMAT),
                "to": datetime.now(tz=UTC).strftime(_TS_FORMAT),
                "limit": str(self._limit),
                "sort": "timestamp:asc",
            }
        )
        return f"{self._url}{_ABSOLUTE}?{params}"

    def _fetch(self, url: str) -> str:
        headers = self._headers()
        if self._fetcher is not None:
            return self._fetcher(url, headers)
        return http_get(url, headers, timeout=self._timeout)

    @staticmethod
    def _messages(payload: str) -> list[dict]:
        """Extract the message documents from a universal search response."""
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return []
        out: list[dict] = []
        for item in data.get("messages", []):
            msg = item.get("message") if isinstance(item, dict) else None
            if isinstance(msg, dict):
                out.append(msg)
        return out

    # -- public API --------------------------------------------------------

    async def events(self) -> AsyncIterator[Event]:
        """Yield events matching the query once (batch mode)."""
        for msg in self._messages(self._fetch(self._relative_url())):
            event = _map_message(msg)
            if event is not None:
                yield event

    async def poll(self, interval: float) -> AsyncIterator[Event]:
        """Poll Graylog forever, yielding only newly-arrived messages.

        The first round uses a relative search; later rounds use an absolute
        search from the newest timestamp seen. Messages on the boundary are
        skipped by `_id`, so none is delivered twice. Runs until the caller
        stops iterating.
        """
        cursor: datetime | None = None
        seen: set[str] = set()

        while True:
            url = self._relative_url() if cursor is None else self._absolute_url(cursor)
            messages = self._messages(self._fetch(url))

            batch_ids: set[str] = set()
            for msg in messages:
                msg_id = str(msg.get("_id") or "")
                if msg_id:
                    batch_ids.add(msg_id)
                    if msg_id in seen:
                        continue
                event = _map_message(msg)
                if event is None:
                    continue
                yield event
                if event.timestamp is not None and (cursor is None or event.timestamp > cursor):
                    cursor = event.timestamp

            if batch_ids:
                seen = batch_ids

            await asyncio.sleep(interval)
