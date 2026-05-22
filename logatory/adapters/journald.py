"""Journald source adapter — reads logs from the systemd journal.

Shells out to `journalctl -o json`; no Python dependency. systemd/Linux
only — on other systems `journalctl` is absent and the adapter raises a
clear error.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from ..models import Event, Severity
from .base import SourceAdapter

# syslog priority (0 emerg … 7 debug) → internal severity
_PRIORITY_MAP = {
    "0": Severity.CRITICAL,
    "1": Severity.CRITICAL,
    "2": Severity.CRITICAL,
    "3": Severity.ERROR,
    "4": Severity.WARNING,
    "5": Severity.INFO,
    "6": Severity.INFO,
    "7": Severity.DEBUG,
}


def _map_entry(entry: dict) -> Event | None:
    """Map one `journalctl -o json` entry to an Event."""
    msg = entry.get("MESSAGE")
    if isinstance(msg, list):
        # journald encodes non-UTF-8 messages as a byte array
        msg = bytes(msg).decode("utf-8", errors="replace")
    if msg is None:
        return None
    message = str(msg)

    severity = _PRIORITY_MAP.get(str(entry.get("PRIORITY", "6")), Severity.INFO)

    timestamp: datetime | None = None
    rt = entry.get("__REALTIME_TIMESTAMP")
    if rt is not None:
        try:
            timestamp = datetime.fromtimestamp(int(rt) / 1_000_000, tz=UTC)
        except (ValueError, OSError, OverflowError):
            timestamp = None

    source = (
        entry.get("_SYSTEMD_UNIT")
        or entry.get("SYSLOG_IDENTIFIER")
        or entry.get("_COMM")
        or "journald"
    )

    parsed = {
        k: entry[k]
        for k in ("_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_HOSTNAME", "_PID", "PRIORITY")
        if k in entry
    }
    cursor = entry.get("__CURSOR")
    if cursor:
        parsed["__cursor"] = cursor

    return Event(
        raw=message,
        source=str(source),
        message=message,
        timestamp=timestamp,
        severity=severity,
        parsed_fields=parsed,
    )


class JournaldAdapter(SourceAdapter):
    """Reads log events from the systemd journal via `journalctl`."""

    def __init__(
        self,
        *,
        unit: str | None = None,
        since: str | None = None,
        lines: int | None = None,
        runner=None,
    ) -> None:
        self._unit = unit
        self._since = since
        self._lines = lines
        self._runner = runner  # injectable for tests: (list[str]) -> str

    def _run(self, extra: list[str]) -> str:
        args = ["journalctl", "-o", "json", "--no-pager"]
        if self._unit:
            args += ["-u", self._unit]
        args += extra
        if self._runner is not None:
            return self._runner(args)
        try:
            result = subprocess.run(args, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            raise RuntimeError(
                "journalctl not found — the journald adapter needs a systemd-based Linux system."
            )
        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"journalctl failed: {detail}")
        return result.stdout

    @staticmethod
    def _parse(output: str) -> list[Event]:
        events: list[Event] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            event = _map_entry(entry)
            if event is not None:
                events.append(event)
        return events

    async def events(self) -> AsyncIterator[Event]:
        """Yield journal entries once (batch mode)."""
        extra: list[str] = []
        if self._since:
            extra += ["--since", self._since]
        if self._lines:
            extra += ["-n", str(self._lines)]
        for event in self._parse(self._run(extra)):
            yield event

    async def poll(self, interval: float) -> AsyncIterator[Event]:
        """Poll the journal forever, yielding only newly-arrived entries.

        Uses journald's native opaque `__CURSOR` via `--after-cursor`, so
        each round delivers exactly the entries after the last one seen —
        no duplicates, no boundary gaps. Runs until the caller stops.
        """
        cursor: str | None = None
        while True:
            if cursor:
                extra = ["--after-cursor", cursor]
            else:
                extra = ["-n", str(self._lines or 20)]
            for event in self._parse(self._run(extra)):
                cur = event.parsed_fields.get("__cursor")
                if cur:
                    cursor = str(cur)
                yield event
            await asyncio.sleep(interval)
