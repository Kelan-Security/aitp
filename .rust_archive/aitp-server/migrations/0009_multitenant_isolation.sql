CREATE TABLE IF NOT EXISTS trust_policies (
    org_id TEXT PRIMARY KEY,
    deny_threshold INTEGER NOT NULL DEFAULT 64,
    monitor_threshold INTEGER NOT NULL DEFAULT 128,
    custom_anomaly_sensitivity TEXT NOT NULL DEFAULT 'medium',
    allowed_intents TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    FOREIGN KEY(org_id) REFERENCES organisations(id) ON DELETE CASCADE
);

-- SQLite does not support simply dropping a primary key, so we create a new table
CREATE TABLE entity_baselines_new (
    org_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    avg_sessions_per_hour REAL NOT NULL DEFAULT 0.0,
    intent_distribution TEXT NOT NULL DEFAULT '{}',
    avg_trust_score REAL NOT NULL DEFAULT 128.0,
    known_peers TEXT NOT NULL DEFAULT '[]',
    avg_payload_bytes REAL NOT NULL DEFAULT 0.0,
    normal_hours TEXT NOT NULL DEFAULT '[]',
    learning_complete INTEGER NOT NULL DEFAULT 0,
    sample_count INTEGER NOT NULL DEFAULT 0,
    last_updated INTEGER NOT NULL,
    PRIMARY KEY (org_id, entity_id),
    FOREIGN KEY(org_id) REFERENCES organisations(id) ON DELETE CASCADE
);

-- Copy data (we'll migrate orphans to a default org via application logic or they drop)
INSERT INTO entity_baselines_new (org_id, entity_id, avg_sessions_per_hour, intent_distribution, avg_trust_score, known_peers, avg_payload_bytes, normal_hours, learning_complete, sample_count, last_updated)
SELECT 'system-default-org', entity_id, avg_sessions_per_hour, intent_distribution, avg_trust_score, known_peers, avg_payload_bytes, normal_hours, learning_complete, sample_count, last_updated
FROM entity_baselines;

DROP TABLE entity_baselines;
ALTER TABLE entity_baselines_new RENAME TO entity_baselines;
