"""Tests for web dashboard routes — HTML pages (ui.py) and HTMX/JSON API (api.py)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from log_analyzer.config import Config
from log_analyzer.models import Finding, FindingSeverity
from log_analyzer.storage.errors_repo import ErrorsRepository
from log_analyzer.storage.findings_repo import FindingsRepository
from log_analyzer.web.app import create_app


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _ts() -> datetime:
    return datetime.now(tz=UTC)


def _seed(db_path: Path) -> None:
    findings = [
        Finding(
            rule_id="SSH_BRUTE",
            severity=FindingSeverity.CRITICAL,
            message="SSH brute force",
            source="auth.log",
            timestamp=_ts(),
        ),
        Finding(
            rule_id="SQL_INJ",
            severity=FindingSeverity.HIGH,
            message="SQL injection",
            source="web.log",
            timestamp=_ts(),
        ),
    ]
    with FindingsRepository(db_path) as repo:
        repo.add_findings(findings)

    with ErrorsRepository(db_path) as repo:
        repo.upsert(
            fingerprint="fp_test",
            error_type="TimeoutError",
            normalized_msg="Query timed out",
            severity="medium",
            source="db.log",
            timestamp=_ts(),
            sample="Query timed out after 30s",
        )


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    cfg = Config(db_path=tmp_path / "test.db")
    with TestClient(create_app(cfg)) as c:
        yield c


@pytest.fixture()
def seeded(tmp_path: Path) -> TestClient:
    db = tmp_path / "test.db"
    _seed(db)
    cfg = Config(db_path=db)
    with TestClient(create_app(cfg)) as c:
        yield c


# ===========================================================================
# HTML pages — ui.py
# ===========================================================================


class TestDashboardPage:
    def test_returns_200(self, client: TestClient) -> None:
        r = client.get("/")
        assert r.status_code == 200

    def test_returns_html(self, client: TestClient) -> None:
        r = client.get("/")
        assert "text/html" in r.headers["content-type"]

    def test_contains_dashboard_markup(self, client: TestClient) -> None:
        r = client.get("/")
        assert "<html" in r.text.lower() or "<!doctype" in r.text.lower()

    def test_empty_db_does_not_crash(self, client: TestClient) -> None:
        r = client.get("/")
        assert r.status_code == 200

    def test_seeded_data_shown(self, seeded: TestClient) -> None:
        r = seeded.get("/")
        assert r.status_code == 200


class TestFindingsPage:
    def test_returns_200(self, client: TestClient) -> None:
        r = client.get("/findings")
        assert r.status_code == 200

    def test_returns_html(self, client: TestClient) -> None:
        r = client.get("/findings")
        assert "text/html" in r.headers["content-type"]

    def test_empty_db_ok(self, client: TestClient) -> None:
        r = client.get("/findings")
        assert r.status_code == 200

    def test_seeded_findings_in_page(self, seeded: TestClient) -> None:
        r = seeded.get("/findings")
        assert r.status_code == 200
        assert "SSH_BRUTE" in r.text or "auth.log" in r.text


class TestErrorsPage:
    def test_returns_200(self, client: TestClient) -> None:
        r = client.get("/errors")
        assert r.status_code == 200

    def test_returns_html(self, client: TestClient) -> None:
        r = client.get("/errors")
        assert "text/html" in r.headers["content-type"]

    def test_empty_db_ok(self, client: TestClient) -> None:
        r = client.get("/errors")
        assert r.status_code == 200

    def test_seeded_errors_in_page(self, seeded: TestClient) -> None:
        r = seeded.get("/errors")
        assert r.status_code == 200
        assert "TimeoutError" in r.text or "fp_test" in r.text


class TestUploadPage:
    def test_returns_200(self, client: TestClient) -> None:
        r = client.get("/upload")
        assert r.status_code == 200

    def test_returns_html(self, client: TestClient) -> None:
        r = client.get("/upload")
        assert "text/html" in r.headers["content-type"]


# ===========================================================================
# Dashboard JSON/HTMX API — api.py
# ===========================================================================


class TestApiStats:
    def test_returns_200(self, client: TestClient) -> None:
        r = client.get("/api/stats")
        assert r.status_code == 200

    def test_empty_db_zeros(self, client: TestClient) -> None:
        r = client.get("/api/stats")
        body = r.json()
        assert body["findings_total"] == 0
        assert body["error_types"] == 0

    def test_seeded_counts(self, seeded: TestClient) -> None:
        r = seeded.get("/api/stats")
        body = r.json()
        assert body["findings_total"] == 2
        assert body["error_types"] == 1
        assert body["findings_critical"] == 1

    def test_response_has_all_fields(self, client: TestClient) -> None:
        r = client.get("/api/stats")
        body = r.json()
        for field in ("findings_total", "findings_critical", "error_types", "error_occurrences"):
            assert field in body


class TestApiTrend:
    def test_returns_200(self, client: TestClient) -> None:
        r = client.get("/api/trend")
        assert r.status_code == 200

    def test_response_shape(self, client: TestClient) -> None:
        r = client.get("/api/trend")
        body = r.json()
        assert "findings" in body
        assert "errors" in body

    def test_custom_days(self, client: TestClient) -> None:
        r = client.get("/api/trend?days=7")
        assert r.status_code == 200

    def test_seeded_trend_data(self, seeded: TestClient) -> None:
        r = seeded.get("/api/trend")
        body = r.json()
        # findings list contains dicts with day/severity/count
        assert isinstance(body["findings"], list)


class TestApiFindings:
    def test_returns_html_partial(self, client: TestClient) -> None:
        r = client.get("/api/findings")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_empty_db_ok(self, client: TestClient) -> None:
        r = client.get("/api/findings")
        assert r.status_code == 200

    def test_filter_by_severity(self, seeded: TestClient) -> None:
        r = seeded.get("/api/findings?severity=critical")
        assert r.status_code == 200
        assert "SSH_BRUTE" in r.text

    def test_filter_by_source(self, seeded: TestClient) -> None:
        r = seeded.get("/api/findings?source=auth.log")
        assert r.status_code == 200

    def test_since_hours_filter(self, seeded: TestClient) -> None:
        r = seeded.get("/api/findings?since_hours=24")
        assert r.status_code == 200


class TestApiErrors:
    def test_returns_html_partial(self, client: TestClient) -> None:
        r = client.get("/api/errors")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_empty_db_ok(self, client: TestClient) -> None:
        r = client.get("/api/errors")
        assert r.status_code == 200

    def test_filter_by_severity(self, seeded: TestClient) -> None:
        r = seeded.get("/api/errors?severity=medium")
        assert r.status_code == 200

    def test_sort_by_count(self, seeded: TestClient) -> None:
        r = seeded.get("/api/errors?sort=count")
        assert r.status_code == 200

    def test_seeded_error_in_partial(self, seeded: TestClient) -> None:
        r = seeded.get("/api/errors")
        assert r.status_code == 200
        assert "TimeoutError" in r.text or "fp_test" in r.text
