"""Tests for the SSH source adapter."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import pytest

from logatory.adapters.ssh import SSHAdapter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _journal_entry(
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


def _jline(**kw) -> str:
    """A single journalctl JSON line, as a streamed connection would deliver it."""
    return json.dumps(_journal_entry(**kw)) + "\n"


class _Runner:
    """Injectable batch ssh stand-in: returns canned output, records calls."""

    def __init__(self, *responses: str) -> None:
        self._responses = list(responses)
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        return self._responses.pop(0) if self._responses else ""


async def _ait(lines: list[str]) -> AsyncIterator[str]:
    for line in lines:
        yield line


class _StreamRunner:
    """Injectable streaming ssh stand-in: yields canned lines per connection."""

    def __init__(self, *connections: list[str]) -> None:
        self._connections = [list(c) for c in connections]
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> AsyncIterator[str]:
        self.calls.append(args)
        lines = self._connections.pop(0) if self._connections else []
        return _ait(lines)


# ---------------------------------------------------------------------------
# Mode resolution
# ---------------------------------------------------------------------------


class TestModeValidation:
    def test_no_source_raises(self):
        with pytest.raises(ValueError):
            SSHAdapter(host="web01")

    def test_path_is_file_mode(self):
        adapter = SSHAdapter(host="web01", path="/var/log/app.log")
        assert adapter._journald is False

    def test_unit_implies_journald(self):
        adapter = SSHAdapter(host="web01", unit="nginx.service")
        assert adapter._journald is True

    def test_journald_flag(self):
        adapter = SSHAdapter(host="web01", use_journald=True)
        assert adapter._journald is True


# ---------------------------------------------------------------------------
# Batch mode — journald
# ---------------------------------------------------------------------------


class TestBatchJournald:
    async def test_maps_journal_entries(self):
        runner = _Runner(_journal(_journal_entry(message="one"), _journal_entry(message="two")))
        adapter = SSHAdapter(host="web01", use_journald=True, runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["one", "two"]

    async def test_source_tagged_with_host(self):
        runner = _Runner(_journal(_journal_entry(unit="nginx.service")))
        adapter = SSHAdapter(host="web01", use_journald=True, runner=runner)
        events = [e async for e in adapter.events()]
        assert events[0].source == "web01:nginx.service"
        assert events[0].parsed_fields["ssh_host"] == "web01"

    async def test_user_prefix_stripped_from_host_label(self):
        runner = _Runner(_journal(_journal_entry()))
        adapter = SSHAdapter(host="deploy@web01", use_journald=True, runner=runner)
        events = [e async for e in adapter.events()]
        assert events[0].parsed_fields["ssh_host"] == "web01"
        assert events[0].source.startswith("web01:")

    async def test_blank_and_garbage_lines_skipped(self):
        runner = _Runner(_journal(_journal_entry(message="ok")) + "\n\nnot-json\n")
        adapter = SSHAdapter(host="web01", use_journald=True, runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["ok"]


# ---------------------------------------------------------------------------
# Batch mode — remote file
# ---------------------------------------------------------------------------


class TestBatchFile:
    async def test_parses_file_lines(self):
        runner = _Runner("alpha\nbeta\ngamma\n")
        adapter = SSHAdapter(host="web01", path="/var/log/app.log", runner=runner)
        events = [e async for e in adapter.events()]
        assert len(events) == 3
        assert [e.message.strip() for e in events] == ["alpha", "beta", "gamma"]

    async def test_file_events_tagged_with_host(self):
        runner = _Runner("alpha\n")
        adapter = SSHAdapter(host="deploy@web01", path="/var/log/app.log", runner=runner)
        events = [e async for e in adapter.events()]
        assert events[0].parsed_fields["ssh_host"] == "web01"


# ---------------------------------------------------------------------------
# Remote command construction
# ---------------------------------------------------------------------------


class TestBatchArgs:
    async def test_journald_batch_command(self):
        runner = _Runner("")
        adapter = SSHAdapter(host="web01", use_journald=True, runner=runner)
        _ = [e async for e in adapter.events()]
        assert runner.calls[0] == [
            "ssh",
            "-o",
            "ConnectTimeout=10",
            "web01",
            "journalctl -o json --no-pager -n 1000",
        ]

    async def test_unit_filter_in_command(self):
        runner = _Runner("")
        adapter = SSHAdapter(host="web01", unit="nginx.service", runner=runner)
        _ = [e async for e in adapter.events()]
        assert runner.calls[0][-1] == "journalctl -o json --no-pager -u nginx.service -n 1000"

    async def test_since_in_command(self):
        runner = _Runner("")
        adapter = SSHAdapter(host="web01", use_journald=True, since="-1h", runner=runner)
        _ = [e async for e in adapter.events()]
        assert "--since -1h" in runner.calls[0][-1]

    async def test_file_batch_command(self):
        runner = _Runner("")
        adapter = SSHAdapter(host="web01", path="/var/log/app.log", runner=runner)
        _ = [e async for e in adapter.events()]
        assert runner.calls[0][-1] == "tail -n 1000 /var/log/app.log"

    async def test_path_with_space_is_quoted(self):
        runner = _Runner("")
        adapter = SSHAdapter(host="web01", path="/var/log/my app.log", runner=runner)
        _ = [e async for e in adapter.events()]
        assert runner.calls[0][-1] == "tail -n 1000 '/var/log/my app.log'"

    async def test_ssh_connection_options_forwarded(self):
        runner = _Runner("")
        adapter = SSHAdapter(
            host="web01",
            use_journald=True,
            port=2222,
            identity="/home/me/key",
            ssh_opts=["ProxyJump=bastion"],
            runner=runner,
        )
        _ = [e async for e in adapter.events()]
        args = runner.calls[0]
        assert args[1:3] == ["-p", "2222"]
        assert args[3:5] == ["-i", "/home/me/key"]
        assert "ProxyJump=bastion" in args
        assert "ConnectTimeout=10" in args


# ---------------------------------------------------------------------------
# Realtime follow — journald
# ---------------------------------------------------------------------------


class TestPollJournald:
    async def test_streams_and_resumes_from_cursor(self):
        runner = _StreamRunner(
            [_jline(message="first", cursor="c1"), _jline(message="second", cursor="c2")],
            [_jline(message="third", cursor="c3")],
        )
        adapter = SSHAdapter(host="web01", use_journald=True, stream_runner=runner)

        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 3:
                break

        assert collected == ["first", "second", "third"]
        # after a dropped connection, reconnect strictly after the last cursor
        assert runner.calls[1][-1] == "journalctl -o json --no-pager -f --after-cursor c2"


# ---------------------------------------------------------------------------
# Realtime follow — remote file
# ---------------------------------------------------------------------------


class TestPollFile:
    async def test_streams_file_and_skips_backfill_on_reconnect(self):
        # the up-front batch read is used once to detect the file's format
        runner = _Runner("seed line\n")
        stream = _StreamRunner(["alpha\n", "beta\n"], ["gamma\n"])
        adapter = SSHAdapter(
            host="web01",
            path="/var/log/app.log",
            runner=runner,
            stream_runner=stream,
        )

        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message.strip())
            if len(collected) >= 3:
                break

        assert collected == ["alpha", "beta", "gamma"]
        # first connection backfills the last N lines; a reconnect does not
        assert stream.calls[0][-1] == "tail -n 1000 -F /var/log/app.log"
        assert stream.calls[1][-1] == "tail -n 0 -F /var/log/app.log"
