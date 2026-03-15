CREATE TABLE IF NOT EXISTS security_incidents (
    id                    TEXT PRIMARY KEY,
    org_id                TEXT NOT NULL,
    severity              TEXT NOT NULL DEFAULT 'medium',
    attack_type           TEXT NOT NULL,
    summary               TEXT,
    entry_point_entity_id TEXT,
    affected_entities     TEXT NOT NULL DEFAULT '[]',
    attack_timeline       TEXT NOT NULL DEFAULT '[]',
    mitre_ttps            TEXT NOT NULL DEFAULT '[]',
    vulnerability         TEXT,
    remediation           TEXT,
    status                TEXT NOT NULL DEFAULT 'open',
    confidence            REAL DEFAULT 0,
    investigation_steps   INTEGER DEFAULT 0,
    detected_at           INTEGER NOT NULL,
    resolved_at           INTEGER
);

CREATE INDEX IF NOT EXISTS idx_incidents_org    ON security_incidents(org_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status);
