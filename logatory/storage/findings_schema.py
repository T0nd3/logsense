FINDINGS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id         TEXT NOT NULL,
    source          TEXT NOT NULL,
    event_timestamp TEXT NOT NULL,
    severity        TEXT NOT NULL,
    message         TEXT NOT NULL,
    raw_event       TEXT,
    created_at      TEXT NOT NULL,
    target          TEXT,
    UNIQUE (rule_id, source, event_timestamp)
);

CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_source     ON findings(source);
CREATE INDEX IF NOT EXISTS idx_findings_rule_id    ON findings(rule_id);
"""
