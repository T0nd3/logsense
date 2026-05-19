BASELINE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS baseline_stats (
    source_key   TEXT NOT NULL,
    feature_name TEXT NOT NULL,
    mean         REAL NOT NULL,
    std          REAL NOT NULL,
    n_samples    INTEGER NOT NULL,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (source_key, feature_name)
);

CREATE TABLE IF NOT EXISTS baseline_observations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_key    TEXT NOT NULL,
    bucket_ts     TEXT NOT NULL,
    features_json TEXT NOT NULL,
    UNIQUE (source_key, bucket_ts)
);

CREATE INDEX IF NOT EXISTS idx_baseline_obs_source
    ON baseline_observations(source_key, bucket_ts);
"""
