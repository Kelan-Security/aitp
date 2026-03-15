CREATE TABLE IF NOT EXISTS entity_baselines (
    entity_id              TEXT PRIMARY KEY,
    avg_sessions_per_hour  REAL NOT NULL DEFAULT 0.0,
    intent_distribution    TEXT NOT NULL DEFAULT '{}',
    avg_trust_score        REAL NOT NULL DEFAULT 128.0,
    known_peers            TEXT NOT NULL DEFAULT '[]',
    avg_payload_bytes      REAL NOT NULL DEFAULT 0.0,
    normal_hours           TEXT NOT NULL DEFAULT '[]',
    learning_complete      INTEGER NOT NULL DEFAULT 0,
    sample_count           INTEGER NOT NULL DEFAULT 0,
    last_updated           INTEGER NOT NULL
);
