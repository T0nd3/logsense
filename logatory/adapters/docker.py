"""Docker source adapter — reads logs from local containers via the Docker API.

No log-aggregation stack (ELK, Loki) required: if your services run in
Docker, this adapter pulls their logs straight from the daemon. Read-only.

Install the optional dependency first: pip install logatory[docker]
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from ..models import Event
from ..parsers.detector import FormatDetector
from ..parsers.registry import get_parser
from .base import SourceAdapter


def _require_docker():
    try:
        import docker

        return docker
    except ImportError:
        raise ImportError("docker SDK is not installed. Run: pip install logatory[docker]")


# RFC3339 timestamp prefix that `docker logs --timestamps` puts on each line.
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s")


def _demux(data: bytes) -> bytes:
    """Strip Docker stream-multiplexing frame headers.

    Containers without a TTY return a multiplexed stream: each frame is an
    8-byte header — [stream type:1][reserved:3][payload size:4 big-endian] —
    followed by the payload. TTY containers return raw bytes (no headers).
    """
    out = bytearray()
    i, n = 0, len(data)
    while i + 8 <= n:
        size = int.from_bytes(data[i + 4 : i + 8], "big")
        i += 8
        out += data[i : i + size]
        i += size
    return bytes(out)


def _parse_ts(token: str) -> datetime | None:
    """Parse an RFC3339(Nano) timestamp; over-long fractions are truncated."""
    token = token.replace("Z", "+00:00")
    token = re.sub(r"(\.\d{6})\d+", r"\1", token)  # microseconds is datetime's limit
    try:
        dt = datetime.fromisoformat(token)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class DockerAdapter(SourceAdapter):
    """Reads log events from Docker containers via the local Docker daemon."""

    def __init__(
        self,
        *,
        name: str | None = None,
        label: str | None = None,
        include_stopped: bool = False,
        tail: int = 200,
        since: datetime | None = None,
        client=None,
    ) -> None:
        self._name = name
        self._label = label
        self._include_stopped = include_stopped
        self._tail = tail
        self._since = since
        self._client = client  # injectable for tests

    def _connect(self):
        if self._client is not None:
            return self._client
        return _require_docker().from_env()

    def _list_containers(self, client) -> list:
        filters: dict = {}
        if self._name:
            filters["name"] = self._name
        if self._label:
            filters["label"] = self._label
        return client.containers.list(all=self._include_stopped, filters=filters or None)

    def _read_lines(
        self, container, *, since: datetime | None, tail: int
    ) -> list[tuple[datetime | None, str]]:
        """Fetch one container's logs as (timestamp, content) pairs."""
        raw = container.logs(
            stdout=True,
            stderr=True,
            timestamps=True,
            tail=tail,
            since=since,
            stream=False,
        )
        if not isinstance(raw, bytes):
            raw = bytes(raw)
        tty = bool((container.attrs or {}).get("Config", {}).get("Tty"))
        text = (raw if tty else _demux(raw)).decode("utf-8", errors="replace")

        pairs: list[tuple[datetime | None, str]] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            m = _TS_RE.match(line)
            if m:
                pairs.append((_parse_ts(m.group(1)), line[m.end() :]))
            else:
                pairs.append((None, line))
        return pairs

    @staticmethod
    def _to_event(parser, ts: datetime | None, content: str, name: str) -> Event | None:
        event = parser.parse(content)
        if event is None:
            return None
        event.source = name
        # Docker's own timestamp is reliable; use it if the parser found none
        if event.timestamp is None and ts is not None:
            event.timestamp = ts
        event.parsed_fields["container"] = name
        return event

    async def events(self) -> AsyncIterator[Event]:
        """Yield every event from matching containers once (batch mode)."""
        client = self._connect()
        for container in self._list_containers(client):
            name = getattr(container, "name", None) or "container"
            pairs = self._read_lines(container, since=self._since, tail=self._tail)
            if not pairs:
                continue
            # Detect the inner log format per container (JSON, Nginx, plaintext, …)
            sample = [content for _, content in pairs[:5] if content.strip()]
            parser = get_parser(FormatDetector().detect(sample), source=name)
            for ts, content in pairs:
                event = self._to_event(parser, ts, content, name)
                if event is not None:
                    yield event

    async def poll(self, interval: float) -> AsyncIterator[Event]:
        """Poll matching containers forever, yielding only newly-arrived events.

        Containers are re-listed every round, so containers started after
        the poll began are picked up automatically. New lines are tracked
        per container via a timestamp cursor — Docker's nanosecond
        timestamps make a same-instant collision effectively impossible.
        Runs until the caller stops iterating.
        """
        client = self._connect()
        cursors: dict[str, datetime] = {}
        parsers: dict = {}

        while True:
            for container in self._list_containers(client):
                name = getattr(container, "name", None) or "container"
                cursor = cursors.get(name)
                pairs = self._read_lines(container, since=cursor or self._since, tail=self._tail)
                if not pairs:
                    continue
                if name not in parsers:
                    sample = [c for _, c in pairs[:5] if c.strip()]
                    parsers[name] = get_parser(FormatDetector().detect(sample), source=name)
                parser = parsers[name]
                newest = cursor
                for ts, content in pairs:
                    if ts is not None and cursor is not None and ts <= cursor:
                        continue  # already delivered in an earlier round
                    event = self._to_event(parser, ts, content, name)
                    if event is not None:
                        yield event
                    if ts is not None and (newest is None or ts > newest):
                        newest = ts
                if newest is not None:
                    cursors[name] = newest

            await asyncio.sleep(interval)
