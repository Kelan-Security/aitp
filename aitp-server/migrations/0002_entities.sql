CREATE TABLE IF NOT EXISTS entities (
    id               TEXT PRIMARY KEY,
    org_id           TEXT,
    name             TEXT NOT NULL,
    entity_type      TEXT NOT NULL,
    public_key       TEXT NOT NULL DEFAULT '',
    department       TEXT,
    clearance_level  INTEGER NOT NULL DEFAULT 0,
    allowed_intents  TEXT NOT NULL DEFAULT '["ModelInference","Heartbeat","DataSync"]',
    trust_score_avg  REAL NOT NULL DEFAULT 128.0,
    session_count    INTEGER NOT NULL DEFAULT 0,
    blocked_count    INTEGER NOT NULL DEFAULT 0,
    quarantined      INTEGER NOT NULL DEFAULT 0,
    last_seen        INTEGER,
    enrolled_at      INTEGER NOT NULL,
    FOREIGN KEY (org_id) REFERENCES organisations(id)
);

CREATE INDEX IF NOT EXISTS idx_entities_org ON entities(org_id);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type);
