"""Tests for the Docker source adapter."""

from __future__ import annotations

from unittest.mock import MagicMock

from logatory.adapters.docker import DockerAdapter, _demux, _parse_ts

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeContainer:
    """Minimal stand-in for a docker SDK Container object."""

    def __init__(self, name: str, log_bytes: bytes, tty: bool = True) -> None:
        self.name = name
        self.attrs = {"Config": {"Tty": tty}}
        self._log_bytes = log_bytes

    def logs(self, **kwargs) -> bytes:
        return self._log_bytes


def _frame(payload: bytes, stream: int = 1) -> bytes:
    """Build one Docker stream-multiplexing frame: 8-byte header + payload."""
    return bytes([stream, 0, 0, 0]) + len(payload).to_bytes(4, "big") + payload


# ---------------------------------------------------------------------------
# Stream de-multiplexing
# ---------------------------------------------------------------------------


class TestDemux:
    def test_single_frame(self):
        payload = b"hello world"
        assert _demux(_frame(payload)) == payload

    def test_multiple_frames(self):
        p1, p2 = b"line one\n", b"line two\n"
        assert _demux(_frame(p1, 1) + _frame(p2, 2)) == p1 + p2

    def test_empty(self):
        assert _demux(b"") == b""

    def test_truncated_trailing_header_ignored(self):
        assert _demux(_frame(b"ok") + b"\x01\x00") == b"ok"


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------


class TestParseTs:
    def test_nanoseconds(self):
        dt = _parse_ts("2026-05-22T10:00:00.123456789Z")
        assert dt is not None
        assert dt.year == 2026 and dt.hour == 10
        assert dt.tzinfo is not None

    def test_no_fraction(self):
        assert _parse_ts("2026-05-22T10:00:00Z") is not None

    def test_offset(self):
        assert _parse_ts("2026-05-22T10:00:00+02:00") is not None

    def test_garbage(self):
        assert _parse_ts("not-a-timestamp") is None


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class TestDockerAdapter:
    def _client(self, *containers) -> MagicMock:
        client = MagicMock()
        client.containers.list.return_value = list(containers)
        return client

    async def test_events_from_tty_container(self):
        log = (
            b"2026-05-22T10:00:00.000000000Z app started\n"
            b"2026-05-22T10:00:01.000000000Z request handled\n"
        )
        client = self._client(_FakeContainer("web-1", log, tty=True))
        events = [e async for e in DockerAdapter(client=client).events()]
        assert len(events) == 2
        assert all(e.source == "web-1" for e in events)
        assert all(e.parsed_fields["container"] == "web-1" for e in events)

    async def test_docker_timestamp_used(self):
        log = b"2026-05-22T10:00:00.000000000Z plain message\n"
        client = self._client(_FakeContainer("svc", log, tty=True))
        events = [e async for e in DockerAdapter(client=client).events()]
        assert events[0].timestamp is not None
        assert events[0].timestamp.year == 2026

    async def test_non_tty_stream_is_demuxed(self):
        content = b"2026-05-22T10:00:00.000000000Z hello from a non-tty service\n"
        client = self._client(_FakeContainer("svc", _frame(content), tty=False))
        events = [e async for e in DockerAdapter(client=client).events()]
        assert len(events) == 1
        assert "hello from a non-tty service" in events[0].message

    async def test_multiple_containers(self):
        c1 = _FakeContainer("alpha", b"2026-05-22T10:00:00.000000000Z one\n", tty=True)
        c2 = _FakeContainer("beta", b"2026-05-22T10:00:00.000000000Z two\n", tty=True)
        events = [e async for e in DockerAdapter(client=self._client(c1, c2)).events()]
        assert {e.source for e in events} == {"alpha", "beta"}

    async def test_name_filter_forwarded(self):
        client = self._client()
        _ = [e async for e in DockerAdapter(name="web", client=client).events()]
        assert client.containers.list.call_args.kwargs["filters"]["name"] == "web"

    async def test_include_stopped_forwarded(self):
        client = self._client()
        _ = [e async for e in DockerAdapter(include_stopped=True, client=client).events()]
        assert client.containers.list.call_args.kwargs["all"] is True


# ---------------------------------------------------------------------------
# Realtime polling
# ---------------------------------------------------------------------------


class _PollContainer:
    """A fake container whose logs() returns a different response per call."""

    def __init__(self, name: str, responses: list[bytes], tty: bool = True) -> None:
        self.name = name
        self.attrs = {"Config": {"Tty": tty}}
        self._responses = list(responses)

    def logs(self, **kwargs) -> bytes:
        return self._responses.pop(0) if self._responses else b""


class TestDockerPoll:
    async def test_poll_dedups_by_timestamp(self):
        r1 = b"2026-05-22T10:00:00.000000000Z first\n2026-05-22T10:00:01.000000000Z second\n"
        r2 = (
            b"2026-05-22T10:00:01.000000000Z second\n"  # boundary repeat — skip
            b"2026-05-22T10:00:02.000000000Z third\n"  # genuinely new — yield
        )
        container = _PollContainer("svc", [r1, r2, b"", b""])
        client = MagicMock()
        client.containers.list.return_value = [container]

        collected: list[str] = []
        async for event in DockerAdapter(client=client).poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 3:
                break

        assert collected == ["first", "second", "third"]

    async def test_poll_picks_up_new_container(self):
        c1 = _PollContainer("alpha", [b"2026-05-22T10:00:00.000000000Z from-a\n", b"", b""])
        c2 = _PollContainer("beta", [b"2026-05-22T10:00:05.000000000Z from-b\n", b"", b""])
        client = MagicMock()
        # beta only shows up on the second poll
        client.containers.list.side_effect = [[c1], [c1, c2], [c1, c2], [c1, c2]]

        collected: list[str] = []
        async for event in DockerAdapter(client=client).poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 2:
                break

        assert set(collected) == {"from-a", "from-b"}
