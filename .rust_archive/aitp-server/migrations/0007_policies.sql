CREATE TABLE IF NOT EXISTS comm_policies (
    id                      TEXT PRIMARY KEY,
    org_id                  TEXT NOT NULL,
    name                    TEXT NOT NULL,
    source_type             TEXT,
    dest_type               TEXT,
    allowed_intents         TEXT NOT NULL DEFAULT '[]',
    max_sessions_per_hour   INTEGER,
    require_clearance_match INTEGER NOT NULL DEFAULT 0,
    enabled                 INTEGER NOT NULL DEFAULT 1,
    priority                INTEGER NOT NULL DEFAULT 100,
    created_at              INTEGER NOT NULL,
    FOREIGN KEY (org_id) REFERENCES organisations(id)
);

CREATE INDEX IF NOT EXISTS idx_policies_org ON comm_policies(org_id);
