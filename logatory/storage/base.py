"""Shared base class for the SQLite-backed repositories.

Every repository in this package boots the same way: open a SQLite
connection, set ``row_factory = sqlite3.Row``, run the standard PRAGMA
bootstrap (:data:`SCHEMA_SQL`) plus zero or more table-creation
scripts, then optionally run light migrations (``ensure_column`` plus
matching index creation).  The lifecycle and the context-manager
protocol are then the same in every repo, only the schema list and the
migration step differ.

Subclasses declare ``_schemas`` (run in order via ``executescript``
after the PRAGMA bootstrap) and may override :meth:`_migrate` to run
any follow-up ``ensure_column`` / index calls.  Everything else —
connection setup, ``close``, ``__enter__`` / ``__exit__`` — is shared.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import ClassVar, Self

from .schema import SCHEMA_SQL


class SqliteRepository:
    """Common lifecycle for SQLite-backed repositories."""

    # Tuple instead of list so a subclass can't accidentally mutate the
    # parent's value through aliasing.  Runs after SCHEMA_SQL, in order.
    _schemas: ClassVar[tuple[str, ...]] = ()

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Open the connection and run the PRAGMA bootstrap, schemas and
        migrations."""
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA_SQL)
        for sql in self._schemas:
            self._conn.executescript(sql)
        self._migrate(self._conn)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Overridable hook
    # ------------------------------------------------------------------

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Run any follow-up migrations after the schemas have executed.

        The default does nothing.  Override to call ``ensure_column`` for
        columns added after the initial release plus any matching index
        creation that depends on the new column.
        """
