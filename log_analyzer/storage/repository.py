from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ..models import Finding
from .schema import SCHEMA_SQL


class FindingsRepository:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA_SQL)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> FindingsRepository:
        self.open()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def save_finding(self, finding: Finding) -> int:
        assert self._conn, "Repository not open"
        cur = self._conn.execute(
            """
            INSERT INTO findings (rule_id, severity, message, source, timestamp, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                finding.rule_id,
                finding.severity.value,
                finding.message,
                finding.source,
                finding.timestamp.isoformat() if finding.timestamp else None,
                json.dumps(finding.details),
            ),
        )
        finding_id = cur.lastrowid
        for event in finding.events:
            self._conn.execute(
                """
                INSERT INTO finding_events
                    (finding_id, timestamp, source, severity, message, raw, parsed_fields)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    event.timestamp.isoformat() if event.timestamp else None,
                    event.source,
                    event.severity.value,
                    event.message,
                    event.raw,
                    json.dumps(event.parsed_fields),
                ),
            )
        self._conn.commit()
        return finding_id

    def list_findings(
        self,
        severity: str | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        assert self._conn, "Repository not open"
        query = "SELECT * FROM findings WHERE 1=1"
        params: list = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if source:
            query += " AND source LIKE ?"
            params.append(f"%{source}%")
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return self._conn.execute(query, params).fetchall()

    def count_findings(self) -> dict[str, int]:
        assert self._conn, "Repository not open"
        rows = self._conn.execute(
            "SELECT severity, COUNT(*) as n FROM findings GROUP BY severity"
        ).fetchall()
        return {row["severity"]: row["n"] for row in rows}
