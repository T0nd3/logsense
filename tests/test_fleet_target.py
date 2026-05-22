"""Tests for persisting the fleet `target` through to SQLite (findings + errors)."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from logatory.errors.fingerprint import fingerprint
from logatory.errors.tracker import ErrorTracker
from logatory.models import Event, Finding, FindingSeverity, Severity
from logatory.storage.errors_repo import ErrorsRepository
from logatory.storage.findings_repo import FindingsRepository

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(target: str | None = None, message: str = "msg") -> Event:
    return Event(
        raw=message,
        source="svc",
        message=message,
        timestamp=datetime.now(tz=UTC),
        severity=Severity.ERROR,
        parsed_fields={"target": target} if target else {},
    )


def _finding(target: str | None = None, rule_id: str = "R1") -> Finding:
    events = [_event(target=target)] if target is not None else []
    return Finding(
        rule_id=rule_id,
        severity=FindingSeverity.HIGH,
        message="m",
        source="svc",
        timestamp=datetime.now(tz=UTC),
        events=events,
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class TestFindingsTarget:
    def test_target_persisted(self, tmp_path):
        with FindingsRepository(tmp_path / "f.db") as repo:
            repo.add_findings([_finding(target="web01")])
            assert repo.list_findings()[0]["target"] == "web01"

    def test_target_null_without_events(self, tmp_path):
        with FindingsRepository(tmp_path / "f.db") as repo:
            repo.add_findings([_finding(target=None)])
            assert repo.list_findings()[0]["target"] is None

    def test_migration_adds_target_to_old_db(self, tmp_path):
        db = tmp_path / "old.db"
        conn = sqlite3.connect(db)
        conn.executescript(
            """
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL, source TEXT NOT NULL,
                event_timestamp TEXT NOT NULL, severity TEXT NOT NULL,
                message TEXT NOT NULL, raw_event TEXT, created_at TEXT NOT NULL,
                UNIQUE (rule_id, source, event_timestamp)
            );
            """
        )
        conn.close()
        with FindingsRepository(db) as repo:
            cols = {r[1] for r in repo._conn.execute("PRAGMA table_info(findings)")}
            assert "target" in cols
            repo.add_findings([_finding(target="web01")])
            assert repo.list_findings()[0]["target"] == "web01"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TestErrorsTarget:
    def test_upsert_stores_target_on_occurrence(self, tmp_path):
        with ErrorsRepository(tmp_path / "e.db") as repo:
            fp = fingerprint("ValueError: bad")
            repo.upsert(
                fingerprint=fp,
                error_type="ValueError",
                normalized_msg="ValueError: bad",
                severity="error",
                source="svc",
                timestamp=datetime.now(tz=UTC),
                sample="ValueError: bad",
                target="web01",
            )
            assert repo.get_occurrences(fp)[0]["target"] == "web01"

    def test_tracker_passes_target_from_event(self, tmp_path):
        with ErrorsRepository(tmp_path / "e.db") as repo:
            row = ErrorTracker(repo).process(_event(target="db01", message="RuntimeError: crash"))
            assert row is not None
            assert repo.get_occurrences(row["fingerprint"])[0]["target"] == "db01"

    def test_target_null_by_default(self, tmp_path):
        with ErrorsRepository(tmp_path / "e.db") as repo:
            fp = fingerprint("ValueError: x")
            repo.upsert(
                fingerprint=fp,
                error_type="ValueError",
                normalized_msg="ValueError: x",
                severity="error",
                source="svc",
                timestamp=datetime.now(tz=UTC),
                sample="ValueError: x",
            )
            assert repo.get_occurrences(fp)[0]["target"] is None

    def test_migration_adds_target_to_old_db(self, tmp_path):
        db = tmp_path / "olderr.db"
        conn = sqlite3.connect(db)
        conn.executescript(
            """
            CREATE TABLE error_occurrences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL, timestamp TEXT NOT NULL,
                source TEXT, sample TEXT NOT NULL, stack_trace TEXT, stack_lang TEXT
            );
            """
        )
        conn.close()
        with ErrorsRepository(db) as repo:
            cols = {r[1] for r in repo._conn.execute("PRAGMA table_info(error_occurrences)")}
            assert "target" in cols
