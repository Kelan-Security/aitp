CREATE TABLE IF NOT EXISTS audit_chain (
    id               TEXT PRIMARY KEY,
    seq              INTEGER,
    org_id           TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    severity         TEXT NOT NULL DEFAULT 'info',
    source_entity_id TEXT,
    session_id       TEXT,
    description      TEXT NOT NULL,
    metadata         TEXT NOT NULL DEFAULT '{}',
    prev_hash        TEXT,
    entry_hash       TEXT NOT NULL,
    created_at       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_org     ON audit_chain(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_time    ON audit_chain(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_entity  ON audit_chain(source_entity_id);
