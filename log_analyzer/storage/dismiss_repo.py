"""Repository for dismissed (suppressed) rules — false-positive management."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from .dismiss_schema import DISMISS_SCHEMA_SQL
from .schema import SCHEMA_SQL

# Sentinel meaning "any source" — stored as empty string so UNIQUE works
_ANY = ""


class DismissRepository:
    """Persist dismissed rule_id / source pairs to SQLite.

    A dismissed entry suppresses *all* future findings that match:
    - rule_id matches exactly
    - source == '' (dismiss for ANY source) OR source matches exactly

    Use `source=None` to dismiss a rule globally (all sources).
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA_SQL)
        self._conn.executescript(DISMISS_SCHEMA_SQL)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> DismissRepository:
        self.open()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def dismiss(
        self,
        rule_id: str,
        source: str | None = None,
        reason: str | None = None,
    ) -> bool:
        """Dismiss a rule.  Returns True if newly inserted, False if already exists."""
        assert self._conn
        src = source or _ANY
        now = datetime.now(tz=UTC).isoformat()
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO dismissed_rules (rule_id, source, reason, created_at) "
            "VALUES (?, ?, ?, ?)",
            (rule_id, src, reason, now),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def undismiss(self, rule_id: str, source: str | None = None) -> bool:
        """Re-enable a previously dismissed rule.  Returns True if a row was removed."""
        assert self._conn
        src = source or _ANY
        cur = self._conn.execute(
            "DELETE FROM dismissed_rules WHERE rule_id = ? AND source = ?",
            (rule_id, src),
        )
        self._conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def is_dismissed(self, rule_id: str, source: str | None = None) -> bool:
        """True if this rule_id + source combination is suppressed.

        A row with source='' suppresses the rule for ALL sources.
        A row with a specific source suppresses only that source.
        """
        assert self._conn
        src = source or _ANY
        row = self._conn.execute(
            "SELECT 1 FROM dismissed_rules "
            "WHERE rule_id = ? AND (source = ? OR source = ?) "
            "LIMIT 1",
            (rule_id, _ANY, src),
        ).fetchone()
        return row is not None

    def list_dismissed(self) -> list[dict]:
        assert self._conn
        rows = self._conn.execute(
            "SELECT * FROM dismissed_rules ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
