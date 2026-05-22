from __future__ import annotations

import sqlite3

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
"""


def ensure_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    """Add a column to an existing table if it is missing — a lightweight migration.

    A fresh database gets the column from its CREATE TABLE; this only matters
    for databases created before the column was introduced, where
    ``CREATE TABLE IF NOT EXISTS`` is a no-op and would not add it.
    """
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
