"""Repository for dismissed (suppressed) rules — false-positive management."""

from __future__ import annotations

from datetime import UTC, datetime

from .base import SqliteRepository
from .dismiss_schema import DISMISS_SCHEMA_SQL

# Sentinel meaning "any source" — stored as empty string so UNIQUE works
_ANY = ""


class DismissRepository(SqliteRepository):
    """Persist dismissed rule_id / source pairs to SQLite.

    A dismissed entry suppresses *all* future findings that match:
    - rule_id matches exactly
    - source == '' (dismiss for ANY source) OR source matches exactly

    Use `source=None` to dismiss a rule globally (all sources).
    """

    _schemas = (DISMISS_SCHEMA_SQL,)

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
