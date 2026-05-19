DISMISS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS dismissed_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT    NOT NULL,
    source      TEXT    NOT NULL DEFAULT '',
    reason      TEXT,
    created_at  TEXT    NOT NULL,
    UNIQUE (rule_id, source)
);
CREATE INDEX IF NOT EXISTS idx_dismissed_rule_id ON dismissed_rules(rule_id);
"""
