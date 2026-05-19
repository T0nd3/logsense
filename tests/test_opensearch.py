from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from log_analyzer.adapters.opensearch import _map_hit, _map_timestamp
from log_analyzer.adapters.opensearch_config import (
    FieldMapping,
    OpenSearchQuery,
    TimeRange,
    build_query_dsl,
)
from log_analyzer.models import Severity

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
    return {"_id": "abc123", "_source": source, "sort": sort_values or ["2026-05-18T10:00:00Z", "abc123"]}


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
        ts = _map_timestamp(1_747_555_200_000)   # ms epoch
        assert ts is not None
        assert ts.tzinfo is not None

    def test_unix_s(self):
        ts = _map_timestamp(1_747_555_200)       # s epoch
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
        hit = _make_hit({
            "@timestamp": "2026-05-18T10:00:00Z",
            "message": "Server started",
            "level": "info",
            "host.name": "web01",
        })
        event = _map_hit(hit, self._mapping(), index="logstash-*")
        assert event is not None
        assert event.message == "Server started"
        assert event.severity == Severity.INFO
        assert event.timestamp is not None

    def test_severity_mapping(self):
        for level, expected in [("error", Severity.ERROR), ("warn", Severity.WARNING), ("fatal", Severity.CRITICAL)]:
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
        hit = _make_hit({
            "@timestamp": "2026-05-18T10:00:00Z",
            "message": "req",
            "status": 200,
            "service": "api",
        })
        event = _map_hit(hit, self._mapping(), index="idx")
        assert event is not None
        assert event.parsed_fields["status"] == 200
        assert event.parsed_fields["service"] == "api"

    def test_source_name_from_field(self):
        # In OpenSearch, "host.name" is stored as a nested dict, not a flat key
        mapping = self._mapping(source_name="host.name")
        hit = _make_hit({
            "@timestamp": "2026-05-18T10:00:00Z",
            "message": "x",
            "host": {"name": "myserver"},
        })
        event = _map_hit(hit, mapping, index="idx")
        assert event is not None
        assert event.source == "myserver"


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
        query = OpenSearchQuery(time_range=TimeRange(since="2026-05-18T00:00:00Z", until="2026-05-18T23:59:59Z"))
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
        from log_analyzer.adapters.opensearch import OpenSearchAdapter
        from log_analyzer.adapters.opensearch_config import OpenSearchQuery

        page1 = [_make_hit({"@timestamp": "2026-05-18T10:00:00Z", "message": f"event {i}"}, sort_values=[f"2026-05-18T10:00:0{i}Z", f"id{i}"]) for i in range(3)]
        page2 = [_make_hit({"@timestamp": "2026-05-18T10:00:03Z", "message": "event 3"}, sort_values=["2026-05-18T10:00:03Z", "id3"])]

        mock_client = MagicMock()
        mock_client.search.side_effect = [
            {"hits": {"hits": page1}},
            {"hits": {"hits": page2}},
            {"hits": {"hits": []}},
        ]
        mock_opensearch_module.OpenSearch.return_value = mock_client

        adapter = OpenSearchAdapter(host="localhost", port=9200, query=OpenSearchQuery(page_size=3))
        events = [e async for e in adapter.events()]
        assert len(events) == 4
        # page1 has 3 hits (= page_size), page2 has 1 hit (< page_size → stops)
        assert mock_client.search.call_count == 2

    async def test_respects_max_events(self, mock_opensearch_module):
        from log_analyzer.adapters.opensearch import OpenSearchAdapter

        hits = [_make_hit({"@timestamp": "2026-05-18T10:00:00Z", "message": f"ev{i}"}) for i in range(10)]
        mock_client = MagicMock()
        mock_client.search.return_value = {"hits": {"hits": hits}}
        mock_opensearch_module.OpenSearch.return_value = mock_client

        adapter = OpenSearchAdapter(host="localhost", port=9200, query=OpenSearchQuery(max_events=3, page_size=10))
        events = [e async for e in adapter.events()]
        assert len(events) == 3
