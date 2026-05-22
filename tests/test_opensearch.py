from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from logatory.adapters.opensearch import _map_hit, _map_timestamp
from logatory.adapters.opensearch_config import (
    FieldMapping,
    OpenSearchQuery,
    TimeRange,
    build_query_dsl,
)
from logatory.models import Severity

# ---------------------------------------------------------------------------
# Fixtures: mock opensearchpy so tests run without the optional dependency
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def mock_opensearch_module():
    """Inject a minimal opensearchpy stub so imports succeed."""
    fake = ModuleType("opensearchpy")
    fake.OpenSearch = MagicMock()
    sys.modules["opensearchpy"] = fake
    yield fake
    sys.modules.pop("opensearchpy", None)


def _make_hit(source: dict, sort_values: list | None = None) -> dict:
    return {
        "_id": "abc123",
        "_source": source,
        "sort": sort_values or ["2026-05-18T10:00:00Z", "abc123"],
    }


def _hit(doc_id: str, ts: str, message: str) -> dict:
    """A hit with an explicit _id — used by the polling tests."""
    return {
        "_id": doc_id,
        "_source": {"@timestamp": ts, "message": message},
        "sort": [ts, doc_id],
    }


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------


class TestMapTimestamp:
    def test_iso_z(self):
        ts = _map_timestamp("2026-05-18T10:00:00Z")
        assert ts is not None
        assert ts.year == 2026 and ts.hour == 10

    def test_iso_with_offset(self):
        ts = _map_timestamp("2026-05-18T10:00:00+02:00")
        assert ts is not None

    def test_unix_ms(self):
        ts = _map_timestamp(1_747_555_200_000)  # ms epoch
        assert ts is not None
        assert ts.tzinfo is not None

    def test_unix_s(self):
        ts = _map_timestamp(1_747_555_200)  # s epoch
        assert ts is not None

    def test_none_input(self):
        assert _map_timestamp(None) is None

    def test_garbage_string(self):
        assert _map_timestamp("not-a-date") is None


# ---------------------------------------------------------------------------
# Hit mapping
# ---------------------------------------------------------------------------


class TestMapHit:
    def _mapping(self, **kwargs) -> FieldMapping:
        return FieldMapping(**kwargs)

    def test_basic_hit(self):
        hit = _make_hit(
            {
                "@timestamp": "2026-05-18T10:00:00Z",
                "message": "Server started",
                "level": "info",
                "host.name": "web01",
            }
        )
        event = _map_hit(hit, self._mapping(), index="logstash-*")
        assert event is not None
        assert event.message == "Server started"
        assert event.severity == Severity.INFO
        assert event.timestamp is not None

    def test_severity_mapping(self):
        for level, expected in [
            ("error", Severity.ERROR),
            ("warn", Severity.WARNING),
            ("fatal", Severity.CRITICAL),
        ]:
            hit = _make_hit({"@timestamp": "2026-05-18T10:00:00Z", "message": "x", "level": level})
            event = _map_hit(hit, self._mapping(), index="idx")
            assert event.severity == expected, f"failed for level={level}"

    def test_missing_message_returns_none(self):
        hit = _make_hit({"@timestamp": "2026-05-18T10:00:00Z"})
        assert _map_hit(hit, self._mapping(), index="idx") is None

    def test_empty_source_returns_none(self):
        hit = {"_id": "x", "_source": {}, "sort": []}
        assert _map_hit(hit, self._mapping(), index="idx") is None

    def test_custom_field_mapping(self):
        mapping = self._mapping(timestamp="ts", message="msg", severity="log_level")
        hit = _make_hit({"ts": "2026-05-18T10:00:00Z", "msg": "hello", "log_level": "error"})
        event = _map_hit(hit, mapping, index="idx")
        assert event is not None
        assert event.message == "hello"
        assert event.severity == Severity.ERROR

    def test_parsed_fields_populated(self):
        hit = _make_hit(
            {
                "@timestamp": "2026-05-18T10:00:00Z",
                "message": "req",
                "status": 200,
                "service": "api",
            }
        )
        event = _map_hit(hit, self._mapping(), index="idx")
        assert event is not None
        assert event.parsed_fields["status"] == 200
        assert event.parsed_fields["service"] == "api"

    def test_source_name_from_field(self):
        # In OpenSearch, "host.name" is stored as a nested dict, not a flat key
        mapping = self._mapping(source_name="host.name")
        hit = _make_hit(
            {
                "@timestamp": "2026-05-18T10:00:00Z",
                "message": "x",
                "host": {"name": "myserver"},
            }
        )
        event = _map_hit(hit, mapping, index="idx")
        assert event is not None
        assert event.source == "myserver"

    def test_hit_carries_doc_id(self):
        # The document _id is needed for realtime polling deduplication
        hit = _make_hit({"@timestamp": "2026-05-18T10:00:00Z", "message": "x"})
        event = _map_hit(hit, self._mapping(), index="idx")
        assert event is not None
        assert event.parsed_fields["_id"] == "abc123"


# ---------------------------------------------------------------------------
# Query DSL builder
# ---------------------------------------------------------------------------


class TestBuildQueryDsl:
    def test_match_all_when_no_filters(self):
        query = OpenSearchQuery()
        dsl = build_query_dsl(query)
        assert dsl["query"] == {"match_all": {}}

    def test_time_range_since(self):
        query = OpenSearchQuery(time_range=TimeRange(since="24h"))
        dsl = build_query_dsl(query)
        must = dsl["query"]["bool"]["must"]
        range_clause = next(c for c in must if "range" in c)
        assert range_clause["range"]["@timestamp"]["gte"] == "now-24h"

    def test_time_range_absolute(self):
        query = OpenSearchQuery(
            time_range=TimeRange(since="2026-05-18T00:00:00Z", until="2026-05-18T23:59:59Z")
        )
        dsl = build_query_dsl(query)
        must = dsl["query"]["bool"]["must"]
        range_clause = next(c for c in must if "range" in c)
        assert range_clause["range"]["@timestamp"]["lte"] == "2026-05-18T23:59:59Z"

    def test_filter_produces_term(self):
        query = OpenSearchQuery(filters=[{"field": "kubernetes.namespace", "value": "production"}])
        dsl = build_query_dsl(query)
        must = dsl["query"]["bool"]["must"]
        term_clauses = [c for c in must if "term" in c]
        assert any(c["term"].get("kubernetes.namespace") == "production" for c in term_clauses)

    def test_sort_includes_tiebreaker(self):
        dsl = build_query_dsl(OpenSearchQuery())
        sort_fields = [next(iter(s.keys())) for s in dsl["sort"]]
        assert "_id" in sort_fields

    def test_custom_timestamp_field(self):
        query = OpenSearchQuery(
            time_range=TimeRange(since="1h"),
            field_mapping=FieldMapping(timestamp="event.created"),
        )
        dsl = build_query_dsl(query)
        must = dsl["query"]["bool"]["must"]
        range_clause = next(c for c in must if "range" in c)
        assert "event.created" in range_clause["range"]


# ---------------------------------------------------------------------------
# Adapter pagination (mocked client)
# ---------------------------------------------------------------------------


class TestOpenSearchAdapterPagination:
    async def test_fetches_all_pages(self, mock_opensearch_module):
        from logatory.adapters.opensearch import OpenSearchAdapter
        from logatory.adapters.opensearch_config import OpenSearchQuery

        page1 = [
            _make_hit(
                {"@timestamp": "2026-05-18T10:00:00Z", "message": f"event {i}"},
                sort_values=[f"2026-05-18T10:00:0{i}Z", f"id{i}"],
            )
            for i in range(3)
        ]
        page2 = [
            _make_hit(
                {"@timestamp": "2026-05-18T10:00:03Z", "message": "event 3"},
                sort_values=["2026-05-18T10:00:03Z", "id3"],
            )
        ]

        mock_client = MagicMock()
        mock_client.search.side_effect = [
            {"hits": {"hits": page1}},
            {"hits": {"hits": page2}},
            {"hits": {"hits": []}},
        ]
        mock_opensearch_module.OpenSearch.return_value = mock_client

        adapter = OpenSearchAdapter(
            host="localhost", port=9200, query=OpenSearchQuery(page_size=3)
        )
        events = [e async for e in adapter.events()]
        assert len(events) == 4
        # page1 has 3 hits (= page_size), page2 has 1 hit (< page_size → stops)
        assert mock_client.search.call_count == 2

    async def test_respects_max_events(self, mock_opensearch_module):
        from logatory.adapters.opensearch import OpenSearchAdapter

        hits = [
            _make_hit({"@timestamp": "2026-05-18T10:00:00Z", "message": f"ev{i}"})
            for i in range(10)
        ]
        mock_client = MagicMock()
        mock_client.search.return_value = {"hits": {"hits": hits}}
        mock_opensearch_module.OpenSearch.return_value = mock_client

        adapter = OpenSearchAdapter(
            host="localhost", port=9200, query=OpenSearchQuery(max_events=3, page_size=10)
        )
        events = [e async for e in adapter.events()]
        assert len(events) == 3


# ---------------------------------------------------------------------------
# Realtime polling (mocked client)
# ---------------------------------------------------------------------------


class TestOpenSearchPoll:
    async def test_poll_dedups_boundary_events(self, mock_opensearch_module):
        """An event on the timestamp boundary must not be delivered twice."""
        from logatory.adapters.opensearch import OpenSearchAdapter

        poll1 = [
            _hit("a", "2026-05-18T10:00:00Z", "ev-a"),
            _hit("b", "2026-05-18T10:00:01Z", "ev-b"),
            _hit("c", "2026-05-18T10:00:02Z", "ev-c"),
        ]
        poll2 = [
            _hit("c", "2026-05-18T10:00:02Z", "ev-c"),  # boundary repeat — skip
            _hit("d", "2026-05-18T10:00:03Z", "ev-d"),  # genuinely new — yield
        ]
        mock_client = MagicMock()
        mock_client.search.side_effect = [
            {"hits": {"hits": poll1}},
            {"hits": {"hits": poll2}},
            {"hits": {"hits": []}},
        ]
        mock_opensearch_module.OpenSearch.return_value = mock_client

        adapter = OpenSearchAdapter(host="localhost", port=9200, query=OpenSearchQuery())
        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 4:
                break

        assert collected == ["ev-a", "ev-b", "ev-c", "ev-d"]

    async def test_poll_continues_through_empty_batches(self, mock_opensearch_module):
        """An empty poll must not stop the loop."""
        from logatory.adapters.opensearch import OpenSearchAdapter

        mock_client = MagicMock()
        mock_client.search.side_effect = [
            {"hits": {"hits": []}},
            {"hits": {"hits": [_hit("a", "2026-05-18T10:00:00Z", "ev-a")]}},
            {"hits": {"hits": []}},
        ]
        mock_opensearch_module.OpenSearch.return_value = mock_client

        adapter = OpenSearchAdapter(host="localhost", port=9200, query=OpenSearchQuery())
        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            break

        assert collected == ["ev-a"]

    async def test_poll_advances_cursor_into_next_query(self, mock_opensearch_module):
        """After a batch, the next query filters gte the latest seen timestamp."""
        from logatory.adapters.opensearch import OpenSearchAdapter

        mock_client = MagicMock()
        mock_client.search.side_effect = [
            {"hits": {"hits": [_hit("a", "2026-05-18T10:00:05Z", "ev-a")]}},
            {"hits": {"hits": [_hit("b", "2026-05-18T10:00:09Z", "ev-b")]}},
            {"hits": {"hits": []}},
        ]
        mock_opensearch_module.OpenSearch.return_value = mock_client

        adapter = OpenSearchAdapter(host="localhost", port=9200, query=OpenSearchQuery())
        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 2:
                break

        second_body = mock_client.search.call_args_list[1].kwargs["body"]
        must = second_body["query"]["bool"]["must"]
        range_clause = next(c for c in must if "range" in c)
        assert range_clause["range"]["@timestamp"]["gte"].startswith("2026-05-18T10:00:05")
