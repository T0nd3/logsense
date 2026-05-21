from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from log_analyzer.models import Finding

from .errors_schema import ERRORS_SCHEMA_SQL
from .findings_schema import FINDINGS_SCHEMA_SQL
from .schema import SCHEMA_SQL

# Severity order for min-severity filtering
_SEV_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def meets_min_severity(finding: Finding, min_severity: str) -> bool:
    """Return True if the finding's severity is >= min_severity."""
    return _SEV_ORDER.get(finding.severity.value, 0) >= _SEV_ORDER.get(min_severity, 2)


class FindingsRepository:
    """Persist rule-engine and anomaly findings to SQLite.

    Uses INSERT OR IGNORE with a UNIQUE(rule_id, source, event_timestamp)
    constraint so that re-scanning the same log file never produces duplicates.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Context-manager / lifecycle
    # ------------------------------------------------------------------

    def open(self) -> None:
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA_SQL)
        self._conn.executescript(ERRORS_SCHEMA_SQL)
        self._conn.executescript(FINDINGS_SCHEMA_SQL)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> FindingsRepository:
        self.open()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def add_findings(self, findings: list[Finding]) -> int:
        """Insert findings, silently skipping duplicates.

        Returns the number of rows actually inserted (duplicates excluded).
        """
        assert self._conn
        now = datetime.now(tz=UTC).isoformat()
        inserted = 0
        for f in findings:
            ts = f.timestamp.isoformat()
            raw = f.events[0].raw[:500] if f.events else None
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO findings
                    (rule_id, source, event_timestamp, severity, message, raw_event, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (f.rule_id, f.source, ts, f.severity.value, f.message[:500], raw, now),
            )
            inserted += cur.rowcount
        self._conn.commit()
        return inserted

    def cleanup_old(self, retention_days: int) -> int:
        """Delete findings older than *retention_days*. Returns deleted count."""
        assert self._conn
        cutoff = (datetime.now(tz=UTC) - timedelta(days=retention_days)).isoformat()
        cur = self._conn.execute("DELETE FROM findings WHERE created_at < ?", (cutoff,))
        self._conn.commit()
        return cur.rowcount

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_findings(
        self,
        severity: str | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        """List findings, newest first.  Optionally filter by severity / source."""
        assert self._conn
        query = "SELECT * FROM findings"
        params: list = []
        conditions: list[str] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if source:
            conditions.append("source = ?")
            params.append(source)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        params.append(limit)
        return self._conn.execute(query, params).fetchall()

    def get_by_id(self, finding_id: int) -> sqlite3.Row | None:
        """Return a single finding by primary-key ID, or None if not found."""
        assert self._conn
        return self._conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()

    def get_by_rule(
        self,
        rule_id: str,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        """Return all occurrences for a given rule ID, newest first."""
        assert self._conn
        return self._conn.execute(
            "SELECT * FROM findings WHERE rule_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
            (rule_id, limit),
        ).fetchall()

    def recent_findings(
        self,
        since_hours: int = 24,
        severity: str | None = None,
        source: str | None = None,
    ) -> list[sqlite3.Row]:
        """Findings created within the last *since_hours* hours."""
        assert self._conn
        cutoff = (datetime.now(tz=UTC) - timedelta(hours=since_hours)).isoformat()
        query = "SELECT * FROM findings WHERE created_at >= ?"
        params: list = [cutoff]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if source:
            query += " AND source = ?"
            params.append(source)
        query += " ORDER BY created_at DESC"
        return self._conn.execute(query, params).fetchall()

    def count_by_rule(self, limit: int = 20) -> list[sqlite3.Row]:
        """Return (rule_id, severity, count) ordered by count desc."""
        assert self._conn
        return self._conn.execute(
            """
            SELECT rule_id, severity, COUNT(*) AS count
              FROM findings
             GROUP BY rule_id, severity
             ORDER BY count DESC
             LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def daily_counts(self, days: int = 14) -> list[dict]:
        """Return daily finding counts grouped by severity for the last *days* days."""
        assert self._conn
        cutoff = (datetime.now(tz=UTC) - timedelta(days=days)).isoformat()
        rows = self._conn.execute(
            """
            SELECT date(created_at) AS day, severity, COUNT(*) AS count
              FROM findings
             WHERE created_at >= ?
             GROUP BY day, severity
             ORDER BY day
            """,
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]

    def summary(self) -> dict:
        assert self._conn
        row = self._conn.execute("SELECT COUNT(*) AS total FROM findings").fetchone()
        by_sev = self._conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
        ).fetchall()
        return {
            "total": row["total"] or 0,
            "by_severity": {r["severity"]: r["n"] for r in by_sev},
        }
