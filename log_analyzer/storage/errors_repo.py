from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .errors_schema import ERRORS_SCHEMA_SQL
from .schema import SCHEMA_SQL


class ErrorsRepository:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA_SQL)
        self._conn.executescript(ERRORS_SCHEMA_SQL)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> ErrorsRepository:
        self.open()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Upsert
    # ------------------------------------------------------------------

    def upsert(
        self,
        fingerprint: str,
        error_type: str,
        normalized_msg: str,
        severity: str,
        source: str,
        timestamp: datetime,
        sample: str,
        stack_trace: str | None = None,
        stack_lang: str | None = None,
    ) -> sqlite3.Row:
        assert self._conn
        ts = timestamp.isoformat()

        existing = self._conn.execute(
            "SELECT fingerprint, sources FROM errors WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()

        if existing:
            sources = json.loads(existing["sources"])
            if source not in sources:
                sources.append(source)
            self._conn.execute(
                """
                UPDATE errors
                   SET last_seen = ?, count = count + 1, sources = ?
                 WHERE fingerprint = ?
                """,
                (ts, json.dumps(sources), fingerprint),
            )
        else:
            self._conn.execute(
                """
                INSERT INTO errors
                    (fingerprint, error_type, normalized_msg, first_seen, last_seen, count, sources, severity)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (fingerprint, error_type, normalized_msg, ts, ts, json.dumps([source]), severity),
            )

        self._conn.execute(
            """
            INSERT INTO error_occurrences (fingerprint, timestamp, source, sample, stack_trace, stack_lang)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (fingerprint, ts, source, sample[:500], stack_trace, stack_lang),
        )
        self._conn.commit()

        return self._conn.execute(
            "SELECT * FROM errors WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_errors(
        self,
        sort: str = "last_seen",
        severity: str | None = None,
        limit: int = 50,
    ) -> list[sqlite3.Row]:
        assert self._conn
        valid_sorts = {"last_seen", "count", "first_seen"}
        order_col = sort if sort in valid_sorts else "last_seen"
        direction = "ASC" if order_col == "first_seen" else "DESC"

        query = "SELECT * FROM errors"
        params: list = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += f" ORDER BY {order_col} {direction} LIMIT ?"
        params.append(limit)
        return self._conn.execute(query, params).fetchall()

    def get_error(self, fingerprint: str) -> sqlite3.Row | None:
        assert self._conn
        return self._conn.execute(
            "SELECT * FROM errors WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()

    def get_occurrences(self, fingerprint: str, limit: int = 20) -> list[sqlite3.Row]:
        assert self._conn
        return self._conn.execute(
            """
            SELECT * FROM error_occurrences
             WHERE fingerprint = ?
             ORDER BY timestamp DESC
             LIMIT ?
            """,
            (fingerprint, limit),
        ).fetchall()

    def new_errors(self, since_hours: int = 168) -> list[sqlite3.Row]:
        """Errors first seen within the last N hours."""
        assert self._conn
        cutoff = (datetime.now(tz=UTC) - timedelta(hours=since_hours)).isoformat()
        return self._conn.execute(
            "SELECT * FROM errors WHERE first_seen >= ? ORDER BY first_seen DESC",
            (cutoff,),
        ).fetchall()

    def regression_errors(self, gap_hours: int = 24) -> list[sqlite3.Row]:
        """Errors that reappeared after a silence of at least gap_hours.

        Heuristic: errors where (last_seen - first_seen) > gap and there is
        an occurrence gap in the timeline. Simplified: first_seen is older
        than gap_hours, but last_seen is within the last gap_hours.
        """
        assert self._conn
        now = datetime.now(tz=UTC)
        recent_cutoff = (now - timedelta(hours=gap_hours)).isoformat()
        old_cutoff = (now - timedelta(hours=gap_hours * 2)).isoformat()
        return self._conn.execute(
            """
            SELECT * FROM errors
             WHERE first_seen <= ?
               AND last_seen  >= ?
             ORDER BY last_seen DESC
            """,
            (old_cutoff, recent_cutoff),
        ).fetchall()

    def summary(self) -> dict:
        assert self._conn
        row = self._conn.execute(
            "SELECT COUNT(*) as total, SUM(count) as occurrences FROM errors"
        ).fetchone()
        by_sev = self._conn.execute(
            "SELECT severity, COUNT(*) as n FROM errors GROUP BY severity"
        ).fetchall()
        return {
            "total_error_types": row["total"] or 0,
            "total_occurrences": row["occurrences"] or 0,
            "by_severity": {r["severity"]: r["n"] for r in by_sev},
        }
