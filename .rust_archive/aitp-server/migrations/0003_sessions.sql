CREATE TABLE IF NOT EXISTS sessions (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL,
    source_entity_id TEXT NOT NULL,
    dest_entity_id   TEXT NOT NULL,
    intent           TEXT NOT NULL,
    trust_score      INTEGER NOT NULL DEFAULT 128,
    verdict          TEXT NOT NULL DEFAULT 'Monitor',
    ai_reasoning     TEXT,
    ai_latency_ms    REAL,
    status           TEXT NOT NULL DEFAULT 'active',
    bytes_tx         INTEGER NOT NULL DEFAULT 0,
    bytes_rx         INTEGER NOT NULL DEFAULT 0,
    anomaly_flags    TEXT NOT NULL DEFAULT '[]',
    started_at       INTEGER NOT NULL,
    ended_at         INTEGER,
    close_reason     TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_org     ON sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status  ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_source  ON sessions(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);
