ERRORS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS errors (
    fingerprint      TEXT PRIMARY KEY,
    error_type       TEXT NOT NULL,
    normalized_msg   TEXT NOT NULL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    count            INTEGER NOT NULL DEFAULT 1,
    sources          TEXT NOT NULL DEFAULT '[]',
    severity         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS error_occurrences (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint  TEXT NOT NULL REFERENCES errors(fingerprint) ON DELETE CASCADE,
    timestamp    TEXT NOT NULL,
    source       TEXT,
    sample       TEXT NOT NULL,
    stack_trace  TEXT,
    stack_lang   TEXT,
    target       TEXT
);

CREATE INDEX IF NOT EXISTS idx_errors_last_seen  ON errors(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_errors_count      ON errors(count DESC);
CREATE INDEX IF NOT EXISTS idx_errors_first_seen ON errors(first_seen ASC);
CREATE INDEX IF NOT EXISTS idx_errors_severity   ON errors(severity);
CREATE INDEX IF NOT EXISTS idx_occ_fingerprint   ON error_occurrences(fingerprint);
CREATE INDEX IF NOT EXISTS idx_occ_timestamp     ON error_occurrences(timestamp DESC);
"""
