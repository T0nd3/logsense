"""Tests for the Grafana Loki source adapter."""

from __future__ import annotations

import json

from logatory.adapters.loki import LokiAdapter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _loki_json(*streams: tuple[dict, list[tuple[int, str]]]) -> str:
    """Render a Loki query_range response.

    Each stream is (labels, [(timestamp_ns, line), ...]).
    """
    return json.dumps(
        {
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": [
                    {"stream": labels, "values": [[str(ns), line] for ns, line in values]}
                    for labels, values in streams
                ],
            },
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
# Response parsing
# ---------------------------------------------------------------------------


class TestEntries:
    def test_parses_and_sorts_by_timestamp(self):
        payload = _loki_json(({"job": "app"}, [(2000, "two"), (1000, "one")]))
        entries = LokiAdapter._entries(payload)
        assert [line for _, line, _ in entries] == ["one", "two"]
        assert entries[0][0] == 1000

    def test_skips_malformed_values(self):
        payload = json.dumps(
            {
                "data": {
                    "result": [
                        {
                            "stream": {},
                            "values": [["notanumber", "x"], ["1000", "ok"], ["missing-line"]],
                        }
                    ]
                }
            }
        )
        entries = LokiAdapter._entries(payload)
        assert [line for _, line, _ in entries] == ["ok"]

    def test_bad_json_returns_empty(self):
        assert LokiAdapter._entries("not json") == []


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------


class TestEvents:
    async def test_yields_events_from_streams(self):
        fetcher = _Fetcher(
            _loki_json(({"job": "app"}, [(1_000_000_000, "one"), (2_000_000_000, "two")]))
        )
        adapter = LokiAdapter(start_ns=0, fetcher=fetcher)
        events = [e async for e in adapter.events()]
        assert [e.message.strip() for e in events] == ["one", "two"]

    async def test_source_from_label(self):
        fetcher = _Fetcher(_loki_json(({"job": "nginx"}, [(1_000_000_000, "x")])))
        adapter = LokiAdapter(start_ns=0, fetcher=fetcher)
        events = [e async for e in adapter.events()]
        assert events[0].source == "nginx"

    async def test_labels_kept_in_parsed_fields(self):
        fetcher = _Fetcher(_loki_json(({"job": "nginx", "env": "prod"}, [(1_000_000_000, "x")])))
        adapter = LokiAdapter(start_ns=0, fetcher=fetcher)
        events = [e async for e in adapter.events()]
        assert events[0].parsed_fields["env"] == "prod"

    async def test_timestamp_falls_back_to_loki_ns(self):
        fetcher = _Fetcher(
            _loki_json(({"job": "app"}, [(1_700_000_000_000_000_000, "plain line")]))
        )
        adapter = LokiAdapter(start_ns=0, fetcher=fetcher)
        events = [e async for e in adapter.events()]
        assert events[0].timestamp is not None

    async def test_empty_result_yields_nothing(self):
        fetcher = _Fetcher(json.dumps({"data": {"result": []}}))
        adapter = LokiAdapter(start_ns=0, fetcher=fetcher)
        events = [e async for e in adapter.events()]
        assert events == []


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------


class TestRequestAndHeaders:
    async def test_request_url_carries_query_params(self):
        fetcher = _Fetcher("")
        adapter = LokiAdapter(start_ns=12345, query='{job="x"}', limit=500, fetcher=fetcher)
        _ = [e async for e in adapter.events()]
        url = fetcher.calls[0][0]
        assert "/loki/api/v1/query_range?" in url
        assert "start=12345" in url
        assert "limit=500" in url
        assert "direction=forward" in url

    def test_bearer_token_header(self):
        assert LokiAdapter(token="abc")._headers()["Authorization"] == "Bearer abc"

    def test_basic_auth_header(self):
        assert (
            LokiAdapter(username="u", password="p")
            ._headers()["Authorization"]
            .startswith("Basic ")
        )

    def test_org_id_header(self):
        assert LokiAdapter(org_id="tenant-1")._headers()["X-Scope-OrgID"] == "tenant-1"


# ---------------------------------------------------------------------------
# Realtime polling
# ---------------------------------------------------------------------------


class TestPoll:
    async def test_streams_and_dedups_boundary(self):
        fetcher = _Fetcher(
            _loki_json(({"job": "app"}, [(1000, "alpha"), (2000, "beta")])),
            _loki_json(({"job": "app"}, [(2000, "beta"), (3000, "gamma")])),
        )
        adapter = LokiAdapter(start_ns=0, fetcher=fetcher)

        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message.strip())
            if len(collected) >= 3:
                break

        assert collected == ["alpha", "beta", "gamma"]

    async def test_poll_advances_start_cursor(self):
        fetcher = _Fetcher(
            _loki_json(({"job": "app"}, [(1000, "alpha"), (2000, "beta")])),
            _loki_json(({"job": "app"}, [(3000, "gamma")])),
        )
        adapter = LokiAdapter(start_ns=0, fetcher=fetcher)

        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message.strip())
            if len(collected) >= 3:
                break

        # the second poll resumes from the newest timestamp of the first
        assert "start=2000" in fetcher.calls[1][0]
