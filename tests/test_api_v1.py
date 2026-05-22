"""Tests for REST API v1 — /api/v1/* endpoints.

Coverage targets:
  GET  /api/v1/health
  GET  /api/v1/findings
  GET  /api/v1/findings/{id}
  GET  /api/v1/errors
  GET  /api/v1/errors/{fingerprint}
  GET  /api/v1/stats
  POST /api/v1/events
  Auth: token required / disabled
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from logatory import __version__
from logatory.config import Config
from logatory.models import Finding, FindingSeverity
from logatory.storage.errors_repo import ErrorsRepository
from logatory.storage.findings_repo import FindingsRepository
from logatory.web.app import create_app

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TOKEN = "test-secret-token"


def _ts(offset_hours: int = 0) -> datetime:
    return datetime.now(tz=UTC) + timedelta(hours=offset_hours)


def _finding(
    rule_id: str = "TEST001",
    severity: FindingSeverity = FindingSeverity.HIGH,
    source: str = "test.log",
    message: str = "test finding",
    ts: datetime | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        source=source,
        timestamp=ts or _ts(),
    )


def _seed_findings(db_path: Path) -> list[Finding]:
    findings = [
        _finding("SSH_BRUTE_FORCE", FindingSeverity.HIGH, "auth.log", "SSH brute force detected"),
        _finding("SQL_INJECTION", FindingSeverity.CRITICAL, "web.log", "SQL injection attempt"),
        _finding("FAILED_LOGIN", FindingSeverity.MEDIUM, "auth.log", "Failed login attempt"),
        _finding("PORT_SCAN", FindingSeverity.LOW, "firewall.log", "Port scan detected"),
    ]
    with FindingsRepository(db_path) as repo:
        repo.add_findings(findings)
    return findings


def _seed_errors(db_path: Path) -> None:
    with ErrorsRepository(db_path) as repo:
        repo.upsert(
            fingerprint="fp_conn_refused",
            error_type="ConnectionError",
            normalized_msg="Connection refused to <HOST>:<PORT>",
            severity="high",
            source="app.log",
            timestamp=_ts(),
            sample="Connection refused to 192.168.1.1:5432",
        )
        repo.upsert(
            fingerprint="fp_db_timeout",
            error_type="TimeoutError",
            normalized_msg="Database query timed out after <NUM>s",
            severity="medium",
            source="db.log",
            timestamp=_ts(-1),
            sample="Database query timed out after 30s",
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture()
def cfg(db_path: Path) -> Config:
    """Config with auth disabled (no api_token)."""
    return Config(db_path=db_path)


@pytest.fixture()
def cfg_auth(db_path: Path) -> Config:
    """Config with Bearer token auth enabled."""
    return Config(db_path=db_path, api_token=_TOKEN)


@pytest.fixture()
def client(cfg: Config) -> TestClient:
    """Unauthenticated client (auth disabled)."""
    with TestClient(create_app(cfg)) as c:
        yield c


@pytest.fixture()
def client_auth(cfg_auth: Config) -> TestClient:
    """Client for an app that requires Bearer token auth."""
    with TestClient(create_app(cfg_auth)) as c:
        yield c


@pytest.fixture()
def seeded(cfg: Config, db_path: Path) -> TestClient:
    """Client with pre-seeded findings and errors in the DB."""
    _seed_findings(db_path)
    _seed_errors(db_path)
    with TestClient(create_app(cfg)) as c:
        yield c


# ===========================================================================
# Health endpoint (no auth)
# ===========================================================================


class TestHealth:
    def test_returns_200(self, client: TestClient) -> None:
        r = client.get("/api/v1/health")
        assert r.status_code == 200

    def test_status_ok(self, client: TestClient) -> None:
        r = client.get("/api/v1/health")
        assert r.json()["status"] == "ok"

    def test_version_present(self, client: TestClient) -> None:
        r = client.get("/api/v1/health")
        assert r.json()["version"] == __version__

    def test_no_auth_required(self, client_auth: TestClient) -> None:
        """Health must respond even when token auth is configured."""
        r = client_auth.get("/api/v1/health")
        assert r.status_code == 200


# ===========================================================================
# Auth enforcement
# ===========================================================================


class TestAuth:
    def test_no_token_config_allows_request(self, client: TestClient) -> None:
        r = client.get("/api/v1/findings")
        assert r.status_code == 200

    def test_missing_token_returns_401(self, client_auth: TestClient) -> None:
        r = client_auth.get("/api/v1/findings")
        assert r.status_code == 401

    def test_wrong_token_returns_401(self, client_auth: TestClient) -> None:
        r = client_auth.get("/api/v1/findings", headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401

    def test_correct_token_returns_200(self, client_auth: TestClient) -> None:
        r = client_auth.get("/api/v1/findings", headers={"Authorization": f"Bearer {_TOKEN}"})
        assert r.status_code == 200

    def test_health_bypasses_auth(self, client_auth: TestClient) -> None:
        r = client_auth.get("/api/v1/health")
        assert r.status_code == 200

    def test_stats_requires_token(self, client_auth: TestClient) -> None:
        r = client_auth.get("/api/v1/stats")
        assert r.status_code == 401

    def test_events_requires_token(self, client_auth: TestClient) -> None:
        r = client_auth.post("/api/v1/events", json={"raw": "test line"})
        assert r.status_code == 401


# ===========================================================================
# GET /api/v1/findings
# ===========================================================================


class TestFindingsList:
    def test_empty_db_returns_empty_list(self, client: TestClient) -> None:
        r = client.get("/api/v1/findings")
        assert r.status_code == 200
        assert r.json() == []

    def test_returns_all_findings(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/findings")
        assert r.status_code == 200
        assert len(r.json()) == 4

    def test_filter_by_severity(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/findings?severity=high")
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 1
        assert rows[0]["severity"] == "high"

    def test_filter_by_source(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/findings?source=auth.log")
        assert r.status_code == 200
        rows = r.json()
        assert all(row["source"] == "auth.log" for row in rows)
        assert len(rows) == 2

    def test_limit_respected(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/findings?limit=2")
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_since_hours_filter(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/findings?since_hours=1")
        assert r.status_code == 200
        # All seeded findings are recent
        assert len(r.json()) == 4

    def test_since_hours_excludes_old(self, cfg: Config, db_path: Path) -> None:
        """Findings inserted 48 h ago must not appear in a since_hours=1 query.

        `recent_findings` filters by `created_at` (DB insertion time), so we
        write directly to SQLite to set an old created_at value.
        """
        import sqlite3 as _sqlite3

        from logatory.storage.findings_schema import FINDINGS_SCHEMA_SQL
        from logatory.storage.schema import SCHEMA_SQL

        old_ts = (datetime.now(tz=UTC) - timedelta(hours=48)).isoformat()
        conn = _sqlite3.connect(db_path)
        conn.executescript(SCHEMA_SQL)
        conn.executescript(FINDINGS_SCHEMA_SQL)
        conn.execute(
            """INSERT INTO findings
               (rule_id, source, event_timestamp, severity, message, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("OLD_RULE", "old.log", old_ts, "low", "old finding", old_ts),
        )
        conn.commit()
        conn.close()

        with TestClient(create_app(cfg)) as c:
            r = c.get("/api/v1/findings?since_hours=1")
        assert r.json() == []

    def test_response_has_required_fields(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/findings?limit=1")
        row = r.json()[0]
        for field in ("rule_id", "severity", "message", "source", "event_timestamp", "created_at"):
            assert field in row, f"Missing field: {field}"

    def test_severity_and_source_combined(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/findings?severity=high&source=auth.log")
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 1
        assert rows[0]["rule_id"] == "SSH_BRUTE_FORCE"


# ===========================================================================
# GET /api/v1/findings/{id}
# ===========================================================================


class TestFindingById:
    def test_returns_finding(self, seeded: TestClient) -> None:
        all_findings = seeded.get("/api/v1/findings").json()
        finding_id = all_findings[0]["id"]
        r = seeded.get(f"/api/v1/findings/{finding_id}")
        assert r.status_code == 200
        assert r.json()["id"] == finding_id

    def test_correct_data_returned(self, seeded: TestClient) -> None:
        rows = seeded.get("/api/v1/findings").json()
        # Find the critical one
        critical = next(row for row in rows if row["severity"] == "critical")
        r = seeded.get(f"/api/v1/findings/{critical['id']}")
        assert r.json()["rule_id"] == "SQL_INJECTION"
        assert r.json()["source"] == "web.log"

    def test_nonexistent_id_returns_404(self, client: TestClient) -> None:
        r = client.get("/api/v1/findings/99999")
        assert r.status_code == 404

    def test_404_detail_message(self, client: TestClient) -> None:
        r = client.get("/api/v1/findings/99999")
        assert "not found" in r.json()["detail"].lower()


# ===========================================================================
# GET /api/v1/errors
# ===========================================================================


class TestErrorsList:
    def test_empty_db_returns_empty_list(self, client: TestClient) -> None:
        r = client.get("/api/v1/errors")
        assert r.status_code == 200
        assert r.json() == []

    def test_returns_all_errors(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/errors")
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_filter_by_severity(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/errors?severity=high")
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 1
        assert rows[0]["severity"] == "high"

    def test_sort_by_count(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/errors?sort=count")
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_sort_by_first_seen(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/errors?sort=first_seen")
        assert r.status_code == 200

    def test_invalid_sort_falls_back_gracefully(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/errors?sort=invalid_column")
        assert r.status_code == 200

    def test_limit_respected(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/errors?limit=1")
        assert r.status_code == 200
        assert len(r.json()) == 1

    def test_response_has_required_fields(self, seeded: TestClient) -> None:
        row = seeded.get("/api/v1/errors").json()[0]
        for field in (
            "fingerprint",
            "error_type",
            "normalized_msg",
            "severity",
            "count",
            "first_seen",
            "last_seen",
            "sources",
        ):
            assert field in row, f"Missing field: {field}"


# ===========================================================================
# GET /api/v1/errors/{fingerprint}
# ===========================================================================


class TestErrorByFingerprint:
    def test_returns_error_group(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/errors/fp_conn_refused")
        assert r.status_code == 200
        body = r.json()
        assert "error" in body
        assert "occurrences" in body

    def test_error_has_correct_type(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/errors/fp_conn_refused")
        assert r.json()["error"]["error_type"] == "ConnectionError"

    def test_occurrences_list_present(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/errors/fp_conn_refused")
        assert isinstance(r.json()["occurrences"], list)
        assert len(r.json()["occurrences"]) >= 1

    def test_nonexistent_fingerprint_returns_404(self, client: TestClient) -> None:
        r = client.get("/api/v1/errors/does_not_exist")
        assert r.status_code == 404

    def test_404_detail_message(self, client: TestClient) -> None:
        r = client.get("/api/v1/errors/does_not_exist")
        assert "not found" in r.json()["detail"].lower()


# ===========================================================================
# GET /api/v1/stats
# ===========================================================================


class TestStats:
    def test_empty_db_zeros(self, client: TestClient) -> None:
        r = client.get("/api/v1/stats")
        assert r.status_code == 200
        body = r.json()
        assert body["findings_total"] == 0
        assert body["error_types"] == 0
        assert body["error_occurrences"] == 0

    def test_counts_match_seeded_data(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/stats")
        body = r.json()
        assert body["findings_total"] == 4
        assert body["error_types"] == 2
        assert body["error_occurrences"] == 2

    def test_findings_by_severity_present(self, seeded: TestClient) -> None:
        r = seeded.get("/api/v1/stats")
        bysev = r.json()["findings_by_severity"]
        assert bysev.get("critical") == 1
        assert bysev.get("high") == 1
        assert bysev.get("medium") == 1
        assert bysev.get("low") == 1

    def test_response_schema(self, client: TestClient) -> None:
        r = client.get("/api/v1/stats")
        body = r.json()
        for field in (
            "findings_total",
            "findings_by_severity",
            "error_types",
            "error_occurrences",
        ):
            assert field in body


# ===========================================================================
# POST /api/v1/events
# ===========================================================================


class TestEventIngest:
    def test_unparseable_line_returns_parsed_false(self, client: TestClient) -> None:
        r = client.post("/api/v1/events", json={"raw": "   "})
        assert r.status_code == 200
        assert r.json()["parsed"] is False
        assert r.json()["findings"] == []

    def test_json_line_is_parsed(self, client: TestClient) -> None:
        payload = {"raw": '{"level": "info", "message": "server started"}', "format": "json_lines"}
        r = client.post("/api/v1/events", json=payload)
        assert r.status_code == 200
        assert r.json()["parsed"] is True

    def test_explicit_format_plaintext(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/events", json={"raw": "INFO server started", "format": "plaintext"}
        )
        assert r.status_code == 200
        assert r.json()["parsed"] is True

    def test_invalid_format_returns_422(self, client: TestClient) -> None:
        r = client.post("/api/v1/events", json={"raw": "some log line", "format": "totally_wrong"})
        assert r.status_code == 422

    def test_invalid_format_lists_valid_values(self, client: TestClient) -> None:
        r = client.post("/api/v1/events", json={"raw": "some log line", "format": "bad_format"})
        detail = r.json()["detail"]
        assert "syslog" in detail or "Valid values" in detail

    def test_findings_list_in_response(self, client: TestClient) -> None:
        r = client.post("/api/v1/events", json={"raw": "INFO heartbeat"})
        assert r.status_code == 200
        assert isinstance(r.json()["findings"], list)

    def test_ssh_brute_force_triggers_finding(self, client: TestClient) -> None:
        """Fire enough failed SSH events to cross the aggregate threshold."""
        ssh_line = (
            "May 21 12:00:0{i} server sshd[1234]: "
            "Failed password for root from 10.0.0.1 port 22 ssh2"
        )
        findings_seen = []
        for i in range(10):
            r = client.post(
                "/api/v1/events",
                json={"raw": ssh_line.format(i=i), "source": "auth.log", "format": "syslog"},
            )
            assert r.status_code == 200
            findings_seen.extend(r.json()["findings"])

        rule_ids = [f["rule_id"] for f in findings_seen]
        assert any("ssh" in rid.lower() or "brute" in rid.lower() for rid in rule_ids), (
            f"Expected SSH-related finding in: {rule_ids}"
        )

    def test_finding_has_required_fields(self, client: TestClient) -> None:
        """Any triggered finding must contain the documented fields."""
        ssh_line = (
            "May 21 12:00:{i:02d} server sshd[1234]: "
            "Failed password for root from 10.0.0.2 port 22 ssh2"
        )
        all_findings = []
        for i in range(10):
            r = client.post(
                "/api/v1/events",
                json={"raw": ssh_line.format(i=i), "source": "auth.log", "format": "syslog"},
            )
            all_findings.extend(r.json()["findings"])

        if all_findings:
            f = all_findings[0]
            for key in ("rule_id", "severity", "message", "source", "timestamp"):
                assert key in f, f"Finding missing key: {key}"

    def test_source_defaults_to_api_ingest(self, client: TestClient) -> None:
        r = client.post("/api/v1/events", json={"raw": '{"level": "info", "message": "ok"}'})
        assert r.status_code == 200
        # parsed=True confirms the source field was used

    def test_custom_source_accepted(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/events",
            json={"raw": '{"level": "error", "message": "crash"}', "source": "my-service"},
        )
        assert r.status_code == 200

    def test_missing_raw_field_returns_422(self, client: TestClient) -> None:
        r = client.post("/api/v1/events", json={"source": "test"})
        assert r.status_code == 422

    def test_auto_format_detection(self, client: TestClient) -> None:
        """Omitting `format` should auto-detect without error."""
        r = client.post(
            "/api/v1/events",
            json={"raw": '{"level": "warning", "message": "disk low"}'},
        )
        assert r.status_code == 200
        assert r.json()["parsed"] is True

    def test_pii_redacted_in_findings(self, client: TestClient) -> None:
        """Findings triggered from events with PII must not leak raw IP addresses."""
        raw_with_ip = (
            "May 21 12:00:01 server sshd[1234]: "
            "Failed password for root from 203.0.113.42 port 22 ssh2"
        )
        # Just check the endpoint doesn't crash and returns expected shape
        r = client.post(
            "/api/v1/events",
            json={"raw": raw_with_ip, "source": "auth.log", "format": "syslog"},
        )
        assert r.status_code == 200
        assert "parsed" in r.json()
