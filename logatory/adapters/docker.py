"""Docker source adapter — reads logs from local containers via the Docker API.

No log-aggregation stack (ELK, Loki) required: if your services run in
Docker, this adapter pulls their logs straight from the daemon. Read-only.

Install the optional dependency first: pip install logatory[docker]
"""

from __future__ import annotations

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

    def _read_lines(self, container) -> list[tuple[datetime | None, str]]:
        """Fetch one container's logs as (timestamp, content) pairs."""
        raw = container.logs(
            stdout=True,
            stderr=True,
            timestamps=True,
            tail=self._tail,
            since=self._since,
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

    async def events(self) -> AsyncIterator[Event]:
        client = self._connect()
        for container in self._list_containers(client):
            name = getattr(container, "name", None) or "container"
            pairs = self._read_lines(container)
            if not pairs:
                continue
            # Detect the inner log format per container (JSON, Nginx, plaintext, …)
            sample = [content for _, content in pairs[:5] if content.strip()]
            parser = get_parser(FormatDetector().detect(sample), source=name)
            for ts, content in pairs:
                event = parser.parse(content)
                if event is None:
                    continue
                event.source = name
                # Docker's own timestamp is reliable; use it if the parser found none
                if event.timestamp is None and ts is not None:
                    event.timestamp = ts
                event.parsed_fields["container"] = name
                yield event
