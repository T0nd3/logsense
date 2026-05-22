"""Tests for the journald source adapter."""

from __future__ import annotations

import json

from logatory.adapters.journald import JournaldAdapter, _map_entry
from logatory.models import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _entry(
    message: str = "service started",
    priority: str = "6",
    unit: str = "app.service",
    cursor: str = "c1",
    ts: str = "1747908000000000",
    **extra,
) -> dict:
    e = {
        "MESSAGE": message,
        "PRIORITY": priority,
        "_SYSTEMD_UNIT": unit,
        "__CURSOR": cursor,
        "__REALTIME_TIMESTAMP": ts,
        "_HOSTNAME": "host1",
    }
    e.update(extra)
    return e


def _journal(*entries: dict) -> str:
    """Render entries as journalctl -o json output (one JSON object per line)."""
    return "\n".join(json.dumps(e) for e in entries)


class _Runner:
    """Injectable journalctl stand-in: returns canned output, records calls."""

    def __init__(self, *responses: str) -> None:
        self._responses = list(responses)
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        return self._responses.pop(0) if self._responses else ""


# ---------------------------------------------------------------------------
# Entry mapping
# ---------------------------------------------------------------------------


class TestMapEntry:
    def test_basic_fields(self):
        ev = _map_entry(_entry(message="hello", unit="nginx.service"))
        assert ev is not None
        assert ev.message == "hello"
        assert ev.source == "nginx.service"
        assert ev.timestamp is not None

    def test_priority_to_severity(self):
        cases = {
            "0": Severity.CRITICAL,
            "2": Severity.CRITICAL,
            "3": Severity.ERROR,
            "4": Severity.WARNING,
            "6": Severity.INFO,
            "7": Severity.DEBUG,
        }
        for prio, expected in cases.items():
            ev = _map_entry(_entry(priority=prio))
            assert ev is not None and ev.severity == expected, f"priority {prio}"

    def test_source_falls_back_to_syslog_identifier(self):
        entry = {"MESSAGE": "x", "PRIORITY": "6", "SYSLOG_IDENTIFIER": "cron"}
        ev = _map_entry(entry)
        assert ev is not None and ev.source == "cron"

    def test_byte_array_message_decoded(self):
        entry = {"MESSAGE": list(b"raw bytes"), "PRIORITY": "6", "_SYSTEMD_UNIT": "x"}
        ev = _map_entry(entry)
        assert ev is not None and ev.message == "raw bytes"

    def test_missing_message_returns_none(self):
        assert _map_entry({"PRIORITY": "6", "_SYSTEMD_UNIT": "x"}) is None

    def test_cursor_kept_in_parsed_fields(self):
        ev = _map_entry(_entry(cursor="s=abc;i=42"))
        assert ev is not None and ev.parsed_fields["__cursor"] == "s=abc;i=42"


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------


class TestEvents:
    async def test_yields_mapped_events(self):
        runner = _Runner(_journal(_entry(message="one"), _entry(message="two")))
        adapter = JournaldAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["one", "two"]

    async def test_unit_filter_forwarded(self):
        runner = _Runner(_journal(_entry()))
        adapter = JournaldAdapter(unit="nginx.service", runner=runner)
        _ = [e async for e in adapter.events()]
        assert "-u" in runner.calls[0]
        assert "nginx.service" in runner.calls[0]

    async def test_blank_and_garbage_lines_skipped(self):
        runner = _Runner(_journal(_entry(message="ok")) + "\n\nnot-json\n")
        adapter = JournaldAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["ok"]


# ---------------------------------------------------------------------------
# Realtime polling
# ---------------------------------------------------------------------------


class TestPoll:
    async def test_poll_advances_cursor(self):
        runner = _Runner(
            _journal(_entry(message="first", cursor="c1"), _entry(message="second", cursor="c2")),
            _journal(_entry(message="third", cursor="c3")),
            "",
        )
        adapter = JournaldAdapter(runner=runner)

        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 3:
                break

        assert collected == ["first", "second", "third"]
        # the second poll must continue strictly after the last cursor
        assert runner.calls[1] == [
            "journalctl",
            "-o",
            "json",
            "--no-pager",
            "--after-cursor",
            "c2",
        ]
