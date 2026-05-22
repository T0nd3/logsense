"""Tests for the Graylog source adapter."""

from __future__ import annotations

import base64
import json

from logatory.adapters.graylog import GraylogAdapter, _map_message, _parse_ts
from logatory.models import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _gl_message(
    message: str = "hello",
    level: int = 6,
    timestamp: str = "2026-05-18T10:00:00.000Z",
    source: str = "web01",
    _id: str = "m1",
    **extra,
) -> dict:
    m = {
        "message": message,
        "level": level,
        "timestamp": timestamp,
        "source": source,
        "_id": _id,
    }
    m.update(extra)
    return m


def _gl_json(*messages: dict) -> str:
    """Render a Graylog universal-search response."""
    return json.dumps(
        {
            "messages": [{"message": m, "index": "graylog_0"} for m in messages],
            "total_results": len(messages),
        }
    )


class _Fetcher:
    """Injectable HTTP stand-in: returns canned bodies, records (url, headers)."""

    def __init__(self, *responses: str) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, headers: dict) -> str:
        self.calls.append((url, headers))
        return self._responses.pop(0) if self._responses else ""


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------


class TestParseTs:
    def test_iso_millis_z(self):
        assert _parse_ts("2026-05-18T10:00:00.123Z") is not None

    def test_iso_no_fraction(self):
        assert _parse_ts("2026-05-18T10:00:00Z") is not None

    def test_garbage_returns_none(self):
        assert _parse_ts("not-a-date") is None

    def test_none_returns_none(self):
        assert _parse_ts(None) is None


# ---------------------------------------------------------------------------
# Message mapping
# ---------------------------------------------------------------------------


class TestMapMessage:
    def test_basic_fields(self):
        ev = _map_message(_gl_message(message="Server started", source="web01"))
        assert ev is not None
        assert ev.message == "Server started"
        assert ev.source == "web01"
        assert ev.timestamp is not None

    def test_level_to_severity(self):
        cases = [
            (0, Severity.CRITICAL),
            (3, Severity.ERROR),
            (4, Severity.WARNING),
            (6, Severity.INFO),
            (7, Severity.DEBUG),
        ]
        for level, expected in cases:
            ev = _map_message(_gl_message(level=level))
            assert ev is not None and ev.severity == expected, f"level {level}"

    def test_missing_message_returns_none(self):
        assert _map_message({"level": 6, "timestamp": "2026-05-18T10:00:00.000Z"}) is None

    def test_missing_level_defaults_to_info(self):
        ev = _map_message({"message": "x", "timestamp": "2026-05-18T10:00:00.000Z"})
        assert ev is not None and ev.severity == Severity.INFO

    def test_parsed_fields_carry_id_and_extras(self):
        ev = _map_message(_gl_message(_id="abc", facility="auth"))
        assert ev is not None
        assert ev.parsed_fields["_id"] == "abc"
        assert ev.parsed_fields["facility"] == "auth"

    def test_message_not_duplicated_in_parsed_fields(self):
        ev = _map_message(_gl_message(message="hello"))
        assert ev is not None and "message" not in ev.parsed_fields


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------


class TestEvents:
    async def test_yields_mapped_messages(self):
        fetcher = _Fetcher(_gl_json(_gl_message(message="one"), _gl_message(message="two")))
        adapter = GraylogAdapter(fetcher=fetcher)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["one", "two"]

    async def test_empty_messages_yields_nothing(self):
        fetcher = _Fetcher(json.dumps({"messages": [], "total_results": 0}))
        adapter = GraylogAdapter(fetcher=fetcher)
        events = [e async for e in adapter.events()]
        assert events == []


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------


class TestRequestAndHeaders:
    async def test_relative_url_carries_params(self):
        fetcher = _Fetcher("")
        adapter = GraylogAdapter(query="error", range_seconds=600, limit=250, fetcher=fetcher)
        _ = [e async for e in adapter.events()]
        url = fetcher.calls[0][0]
        assert "/api/search/universal/relative?" in url
        assert "range=600" in url
        assert "limit=250" in url
        assert "query=error" in url

    def test_token_auth_uses_token_as_password(self):
        headers = GraylogAdapter(token="mytoken")._headers()
        decoded = base64.b64decode(headers["Authorization"].split()[1]).decode()
        assert decoded == "mytoken:token"

    def test_basic_auth_header(self):
        headers = GraylogAdapter(username="u", password="p")._headers()
        assert headers["Authorization"].startswith("Basic ")

    def test_requested_by_header_always_present(self):
        assert GraylogAdapter()._headers()["X-Requested-By"] == "logatory"


# ---------------------------------------------------------------------------
# Realtime polling
# ---------------------------------------------------------------------------


class TestPoll:
    async def test_dedups_by_id_and_switches_to_absolute(self):
        fetcher = _Fetcher(
            _gl_json(
                _gl_message(_id="a", message="ev-a", timestamp="2026-05-18T10:00:00.000Z"),
                _gl_message(_id="b", message="ev-b", timestamp="2026-05-18T10:00:01.000Z"),
            ),
            _gl_json(
                _gl_message(_id="b", message="ev-b", timestamp="2026-05-18T10:00:01.000Z"),
                _gl_message(_id="c", message="ev-c", timestamp="2026-05-18T10:00:02.000Z"),
            ),
        )
        adapter = GraylogAdapter(fetcher=fetcher)

        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 3:
                break

        assert collected == ["ev-a", "ev-b", "ev-c"]
        # first poll is a relative search, later polls are absolute from the cursor
        assert "/relative?" in fetcher.calls[0][0]
        assert "/absolute?" in fetcher.calls[1][0]
