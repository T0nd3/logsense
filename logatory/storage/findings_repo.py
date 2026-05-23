from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from logatory.models import Finding, finding_severity_level

from .base import SqliteRepository
from .errors_schema import ERRORS_SCHEMA_SQL
from .findings_schema import FINDINGS_SCHEMA_SQL
from .schema import ensure_column


def meets_min_severity(finding: Finding, min_severity: str) -> bool:
    """Return True if the finding's severity is >= min_severity.

    Unknown *min_severity* strings fall back to "high" (level 2)."""
    return finding.severity.level >= finding_severity_level(min_severity, default=2)


class FindingsRepository(SqliteRepository):
    """Persist rule-engine and anomaly findings to SQLite.

    Uses INSERT OR IGNORE with a UNIQUE(rule_id, source, event_timestamp)
    constraint so that re-scanning the same log file never produces duplicates.
    """

    _schemas = (ERRORS_SCHEMA_SQL, FINDINGS_SCHEMA_SQL)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        ensure_column(conn, "findings", "target", "TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)")

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
            target = f.events[0].parsed_fields.get("target") if f.events else None
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO findings
                    (rule_id, source, event_timestamp, severity, message,
                     raw_event, created_at, target)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (f.rule_id, f.source, ts, f.severity.value, f.message[:500], raw, now, target),
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
        targets: list[str] | None = None,
    ) -> list[sqlite3.Row]:
        """List findings, newest first. Optionally filter by severity / source / targets."""
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
        if targets:
            conditions.append(f"target IN ({','.join('?' * len(targets))})")
            params.extend(targets)
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

    def count_by_rule(self, limit: int = 20, sort: str = "count") -> list[sqlite3.Row]:
        """Return (rule_id, severity, count) for the top rules.

        sort="count"    → most frequent first (default)
        sort="severity" → most severe first (critical → low), then by count
        """
        assert self._conn
        if sort == "severity":
            order_by = (
                "ORDER BY CASE severity "
                "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, count DESC"
            )
        else:
            order_by = "ORDER BY count DESC"
        return self._conn.execute(
            f"""
            SELECT rule_id, severity, COUNT(*) AS count
              FROM findings
             GROUP BY rule_id, severity
             {order_by}
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
