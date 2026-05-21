from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from ..anomaly.baseline import BaselineStats, FeatureStat
from .baseline_schema import BASELINE_SCHEMA_SQL
from .errors_schema import ERRORS_SCHEMA_SQL
from .schema import SCHEMA_SQL


class BaselineRepository:
    """Persist anomaly detection baseline data in SQLite."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA_SQL)
        self._conn.executescript(ERRORS_SCHEMA_SQL)
        self._conn.executescript(BASELINE_SCHEMA_SQL)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> BaselineRepository:
        self.open()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Observations (raw bucket feature vectors)
    # ------------------------------------------------------------------

    def add_observations(
        self,
        source_key: str,
        feature_dicts: list[dict[str, float]],
        bucket_timestamps: list[datetime],
    ) -> int:
        """Insert bucket feature dicts; skip duplicates (same source_key + bucket_ts).

        Returns the number of newly inserted rows.
        """
        assert self._conn
        inserted = 0
        for ts, fd in zip(bucket_timestamps, feature_dicts):
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO baseline_observations (source_key, bucket_ts, features_json)
                VALUES (?, ?, ?)
                """,
                (source_key, ts.isoformat(), json.dumps(fd)),
            )
            inserted += cur.rowcount
        self._conn.commit()
        return inserted

    def get_observation_count(self, source_key: str) -> int:
        assert self._conn
        return self._conn.execute(
            "SELECT COUNT(*) FROM baseline_observations WHERE source_key = ?",
            (source_key,),
        ).fetchone()[0]

    def get_all_feature_dicts(self, source_key: str) -> list[dict[str, float]]:
        assert self._conn
        rows = self._conn.execute(
            "SELECT features_json FROM baseline_observations WHERE source_key = ? ORDER BY bucket_ts",
            (source_key,),
        ).fetchall()
        return [json.loads(r["features_json"]) for r in rows]

    # ------------------------------------------------------------------
    # Aggregated stats (mean / std per feature)
    # ------------------------------------------------------------------

    def update_stats(self, stats: BaselineStats) -> None:
        assert self._conn
        ts = datetime.now(tz=UTC).isoformat()
        for feature_name, stat in stats.features.items():
            self._conn.execute(
                """
                INSERT OR REPLACE INTO baseline_stats
                    (source_key, feature_name, mean, std, n_samples, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (stats.source_key, feature_name, stat.mean, stat.std, stat.n, ts),
            )
        self._conn.commit()

    def get_stats(self, source_key: str) -> BaselineStats | None:
        assert self._conn
        rows = self._conn.execute(
            "SELECT * FROM baseline_stats WHERE source_key = ?",
            (source_key,),
        ).fetchall()
        if not rows:
            return None
        features = {
            r["feature_name"]: FeatureStat(mean=r["mean"], std=r["std"], n=r["n_samples"])
            for r in rows
        }
        n_buckets = self.get_observation_count(source_key)
        return BaselineStats(source_key=source_key, n_buckets=n_buckets, features=features)

    # ------------------------------------------------------------------
    # Source management
    # ------------------------------------------------------------------

    def list_sources(self) -> list[dict]:
        assert self._conn
        rows = self._conn.execute(
            """
            SELECT
                source_key,
                COUNT(*) AS n_buckets,
                MAX(updated_at) AS updated_at
            FROM baseline_stats
            GROUP BY source_key
            ORDER BY updated_at DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_source(self, source_key: str) -> None:
        assert self._conn
        self._conn.execute("DELETE FROM baseline_stats WHERE source_key = ?", (source_key,))
        self._conn.execute("DELETE FROM baseline_observations WHERE source_key = ?", (source_key,))
        self._conn.commit()
