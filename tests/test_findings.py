"""Tests for Finding persistence — FindingsRepository and meets_min_severity."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logsense.models import Event, Finding, FindingSeverity, Severity
from logsense.storage.findings_repo import FindingsRepository, meets_min_severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _finding_with_event(rule_id: str = "TEST002") -> Finding:
    ev = Event(raw="raw log line", source="test.log", message="msg", severity=Severity.ERROR)
    return Finding(
        rule_id=rule_id,
        severity=FindingSeverity.CRITICAL,
        message="critical finding",
        source="test.log",
        timestamp=_ts(),
        events=[ev],
    )


@pytest.fixture()
def repo(tmp_path: Path) -> FindingsRepository:
    r = FindingsRepository(tmp_path / "test.db")
    r.open()
    yield r
    r.close()


# ---------------------------------------------------------------------------
# meets_min_severity
# ---------------------------------------------------------------------------


class TestMeetsMinSeverity:
    def test_critical_meets_high(self):
        f = _finding(severity=FindingSeverity.CRITICAL)
        assert meets_min_severity(f, "high") is True

    def test_high_meets_high(self):
        f = _finding(severity=FindingSeverity.HIGH)
        assert meets_min_severity(f, "high") is True

    def test_medium_does_not_meet_high(self):
        f = _finding(severity=FindingSeverity.MEDIUM)
        assert meets_min_severity(f, "high") is False

    def test_low_does_not_meet_high(self):
        f = _finding(severity=FindingSeverity.LOW)
        assert meets_min_severity(f, "high") is False

    def test_low_meets_low(self):
        f = _finding(severity=FindingSeverity.LOW)
        assert meets_min_severity(f, "low") is True

    def test_medium_meets_medium(self):
        f = _finding(severity=FindingSeverity.MEDIUM)
        assert meets_min_severity(f, "medium") is True

    def test_high_meets_medium(self):
        f = _finding(severity=FindingSeverity.HIGH)
        assert meets_min_severity(f, "medium") is True

    def test_medium_does_not_meet_critical(self):
        f = _finding(severity=FindingSeverity.MEDIUM)
        assert meets_min_severity(f, "critical") is False

    def test_critical_meets_critical(self):
        f = _finding(severity=FindingSeverity.CRITICAL)
        assert meets_min_severity(f, "critical") is True

    def test_unknown_min_severity_defaults_to_high(self):
        """Unknown min-severity string falls back to 'high' threshold (order 2)."""
        f_low = _finding(severity=FindingSeverity.LOW)
        f_high = _finding(severity=FindingSeverity.HIGH)
        assert meets_min_severity(f_low, "nonsense") is False
        assert meets_min_severity(f_high, "nonsense") is True


# ---------------------------------------------------------------------------
# FindingsRepository — lifecycle
# ---------------------------------------------------------------------------


class TestRepositoryLifecycle:
    def test_open_creates_table(self, tmp_path: Path):
        db = tmp_path / "test.db"
        repo = FindingsRepository(db)
        repo.open()
        conn = sqlite3.connect(db)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        repo.close()
        assert "findings" in tables

    def test_context_manager(self, tmp_path: Path):
        db = tmp_path / "test.db"
        with FindingsRepository(db) as repo:
            assert repo._conn is not None
        assert repo._conn is None

    def test_double_close_is_safe(self, repo: FindingsRepository):
        repo.close()
        repo.close()  # should not raise


# ---------------------------------------------------------------------------
# add_findings
# ---------------------------------------------------------------------------


class TestAddFindings:
    def test_insert_single(self, repo: FindingsRepository):
        n = repo.add_findings([_finding()])
        assert n == 1

    def test_insert_multiple(self, repo: FindingsRepository):
        findings = [_finding(rule_id=f"R{i}") for i in range(5)]
        n = repo.add_findings(findings)
        assert n == 5

    def test_returns_zero_for_empty_list(self, repo: FindingsRepository):
        assert repo.add_findings([]) == 0

    def test_duplicate_is_ignored(self, repo: FindingsRepository):
        f = _finding()
        repo.add_findings([f])
        n = repo.add_findings([f])  # same rule_id + source + timestamp
        assert n == 0

    def test_same_rule_different_timestamp_is_new(self, repo: FindingsRepository):
        f1 = _finding(ts=_ts(0))
        f2 = _finding(ts=_ts(1))  # 1 hour later
        repo.add_findings([f1])
        n = repo.add_findings([f2])
        assert n == 1

    def test_same_timestamp_different_rule_is_new(self, repo: FindingsRepository):
        ts = _ts()
        f1 = _finding(rule_id="R1", ts=ts)
        f2 = _finding(rule_id="R2", ts=ts)
        n = repo.add_findings([f1, f2])
        assert n == 2

    def test_raw_event_stored(self, repo: FindingsRepository):
        f = _finding_with_event()
        repo.add_findings([f])
        row = repo.list_findings()[0]
        assert row["raw_event"] == "raw log line"

    def test_raw_event_none_when_no_events(self, repo: FindingsRepository):
        f = _finding()
        repo.add_findings([f])
        row = repo.list_findings()[0]
        assert row["raw_event"] is None

    def test_message_truncated_to_500(self, repo: FindingsRepository):
        f = _finding(message="x" * 600)
        repo.add_findings([f])
        row = repo.list_findings()[0]
        assert len(row["message"]) == 500

    def test_rescan_same_file_no_duplicates(self, repo: FindingsRepository):
        """Simulates scanning the same log file twice."""
        findings = [_finding(rule_id=f"R{i}") for i in range(3)]
        repo.add_findings(findings)
        n_second = repo.add_findings(findings)
        assert n_second == 0
        assert repo.summary()["total"] == 3


# ---------------------------------------------------------------------------
# cleanup_old
# ---------------------------------------------------------------------------


class TestCleanupOld:
    def _insert_old(self, repo: FindingsRepository, days_ago: int) -> None:
        """Directly insert a finding with a past created_at timestamp."""
        assert repo._conn
        old_ts = (datetime.now(tz=UTC) - timedelta(days=days_ago)).isoformat()
        repo._conn.execute(
            """
            INSERT OR IGNORE INTO findings
                (rule_id, source, event_timestamp, severity, message, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (f"OLD_{days_ago}", "test.log", old_ts, "low", "old finding", old_ts),
        )
        repo._conn.commit()

    def test_deletes_old_findings(self, repo: FindingsRepository):
        self._insert_old(repo, days_ago=40)
        deleted = repo.cleanup_old(retention_days=30)
        assert deleted == 1

    def test_keeps_recent_findings(self, repo: FindingsRepository):
        self._insert_old(repo, days_ago=10)
        deleted = repo.cleanup_old(retention_days=30)
        assert deleted == 0

    def test_boundary_exactly_at_retention(self, repo: FindingsRepository):
        # Exactly at the boundary — should be deleted (strictly older-than)
        self._insert_old(repo, days_ago=31)
        deleted = repo.cleanup_old(retention_days=30)
        assert deleted == 1

    def test_returns_zero_when_nothing_to_delete(self, repo: FindingsRepository):
        repo.add_findings([_finding()])
        deleted = repo.cleanup_old(retention_days=30)
        assert deleted == 0

    def test_mixed_old_and_new(self, repo: FindingsRepository):
        self._insert_old(repo, days_ago=60)
        self._insert_old(repo, days_ago=5)
        deleted = repo.cleanup_old(retention_days=30)
        assert deleted == 1
        assert repo.summary()["total"] == 1


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------


class TestListFindings:
    def test_returns_all_by_default(self, repo: FindingsRepository):
        repo.add_findings([_finding(rule_id=f"R{i}") for i in range(3)])
        assert len(repo.list_findings()) == 3

    def test_filter_by_severity(self, repo: FindingsRepository):
        repo.add_findings(
            [
                _finding(rule_id="R1", severity=FindingSeverity.HIGH),
                _finding(rule_id="R2", severity=FindingSeverity.CRITICAL),
                _finding(rule_id="R3", severity=FindingSeverity.LOW),
            ]
        )
        rows = repo.list_findings(severity="high")
        assert len(rows) == 1
        assert rows[0]["rule_id"] == "R1"

    def test_filter_by_source(self, repo: FindingsRepository):
        repo.add_findings(
            [
                _finding(rule_id="R1", source="app.log"),
                _finding(rule_id="R2", source="access.log"),
            ]
        )
        rows = repo.list_findings(source="app.log")
        assert len(rows) == 1

    def test_limit_respected(self, repo: FindingsRepository):
        repo.add_findings([_finding(rule_id=f"R{i}", ts=_ts(i)) for i in range(10)])
        assert len(repo.list_findings(limit=5)) == 5

    def test_ordered_newest_first(self, repo: FindingsRepository):
        # Insert OLD in one call, then NEW in a separate call so created_at differs
        f_old = _finding(rule_id="OLD", ts=_ts(-2))
        f_new = _finding(rule_id="NEW", ts=_ts(0))
        repo.add_findings([f_old])
        repo.add_findings([f_new])
        rows = repo.list_findings()
        # NEW was inserted later → higher id → appears first (ORDER BY created_at DESC, id DESC)
        assert rows[0]["rule_id"] == "NEW"

    def test_empty_returns_empty_list(self, repo: FindingsRepository):
        assert repo.list_findings() == []


# ---------------------------------------------------------------------------
# recent_findings
# ---------------------------------------------------------------------------


class TestRecentFindings:
    def _insert_at(self, repo: FindingsRepository, rule_id: str, hours_ago: int) -> None:
        assert repo._conn
        past = (datetime.now(tz=UTC) - timedelta(hours=hours_ago)).isoformat()
        repo._conn.execute(
            """
            INSERT OR IGNORE INTO findings
                (rule_id, source, event_timestamp, severity, message, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (rule_id, "test.log", past, "high", "msg", past),
        )
        repo._conn.commit()

    def test_returns_recent(self, repo: FindingsRepository):
        self._insert_at(repo, "RECENT", hours_ago=1)
        self._insert_at(repo, "OLD", hours_ago=48)
        rows = repo.recent_findings(since_hours=24)
        assert len(rows) == 1
        assert rows[0]["rule_id"] == "RECENT"

    def test_severity_filter(self, repo: FindingsRepository):
        self._insert_at(repo, "HIGH_R", hours_ago=1)
        assert repo._conn
        repo._conn.execute("UPDATE findings SET severity = 'critical' WHERE rule_id = 'HIGH_R'")
        repo._conn.commit()
        rows = repo.recent_findings(since_hours=24, severity="high")
        assert len(rows) == 0


# ---------------------------------------------------------------------------
# count_by_rule
# ---------------------------------------------------------------------------


class TestCountByRule:
    def test_counts_correctly(self, repo: FindingsRepository):
        # Two findings for R1 at different timestamps, one for R2
        repo.add_findings(
            [
                _finding(rule_id="R1", ts=_ts(0)),
                _finding(rule_id="R1", ts=_ts(1)),
                _finding(rule_id="R2", ts=_ts(0)),
            ]
        )
        rows = repo.count_by_rule()
        counts = {r["rule_id"]: r["count"] for r in rows}
        assert counts["R1"] == 2
        assert counts["R2"] == 1

    def test_ordered_by_count_desc(self, repo: FindingsRepository):
        repo.add_findings(
            [
                _finding(rule_id="RARE", ts=_ts(0)),
                _finding(rule_id="FREQ", ts=_ts(0)),
                _finding(rule_id="FREQ", ts=_ts(1)),
                _finding(rule_id="FREQ", ts=_ts(2)),
            ]
        )
        rows = repo.count_by_rule()
        assert rows[0]["rule_id"] == "FREQ"


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------


class TestSummary:
    def test_empty_db(self, repo: FindingsRepository):
        s = repo.summary()
        assert s["total"] == 0
        assert s["by_severity"] == {}

    def test_summary_counts(self, repo: FindingsRepository):
        repo.add_findings(
            [
                _finding(rule_id="R1", severity=FindingSeverity.HIGH),
                _finding(rule_id="R2", severity=FindingSeverity.HIGH, ts=_ts(1)),
                _finding(rule_id="R3", severity=FindingSeverity.CRITICAL),
            ]
        )
        s = repo.summary()
        assert s["total"] == 3
        assert s["by_severity"]["high"] == 2
        assert s["by_severity"]["critical"] == 1
