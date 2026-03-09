/// Run all database migrations (idempotent).
pub async fn run(pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
    // Enable WAL mode and foreign keys
    sqlx::query("PRAGMA journal_mode=WAL;").execute(pool).await?;
    sqlx::query("PRAGMA foreign_keys=ON;").execute(pool).await?;

    // ── Core identity registry ──
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS organisations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            gemini_api_key_enc TEXT,
            trust_mode TEXT DEFAULT 'hybrid',
            created_at INTEGER NOT NULL
        )
    "#).execute(pool).await?;

    // ── Entity registry ──
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS entities (
            id TEXT PRIMARY KEY,
            org_id TEXT REFERENCES organisations(id),
            name TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            public_key TEXT NOT NULL,
            department TEXT,
            clearance_level INTEGER DEFAULT 0,
            allowed_intents TEXT DEFAULT '["ModelInference","Heartbeat","DataSync"]',
            trust_score_avg REAL DEFAULT 128,
            session_count INTEGER DEFAULT 0,
            blocked_count INTEGER DEFAULT 0,
            quarantined INTEGER DEFAULT 0,
            last_seen INTEGER,
            enrolled_at INTEGER NOT NULL
        )
    "#).execute(pool).await?;

    // ── Sessions ──
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            source_entity_id TEXT NOT NULL,
            dest_entity_id TEXT NOT NULL,
            intent TEXT NOT NULL,
            trust_score INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            ai_reasoning TEXT,
            ai_latency_ms REAL,
            status TEXT DEFAULT 'active',
            bytes_tx INTEGER DEFAULT 0,
            bytes_rx INTEGER DEFAULT 0,
            anomaly_flags TEXT DEFAULT '[]',
            started_at INTEGER NOT NULL,
            ended_at INTEGER,
            close_reason TEXT
        )
    "#).execute(pool).await?;

    // ── Immutable audit chain ──
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS audit_chain (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_entity_id TEXT,
            session_id TEXT,
            description TEXT NOT NULL,
            metadata TEXT DEFAULT '{}',
            prev_hash TEXT,
            entry_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    "#).execute(pool).await?;

    // ── Entity baselines ──
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS entity_baselines (
            entity_id TEXT PRIMARY KEY,
            avg_sessions_per_hour REAL DEFAULT 0,
            intent_distribution TEXT DEFAULT '{}',
            avg_trust_score REAL DEFAULT 128,
            known_peers TEXT DEFAULT '[]',
            avg_payload_bytes REAL DEFAULT 0,
            normal_hours TEXT DEFAULT '[]',
            learning_complete INTEGER DEFAULT 0,
            sample_count INTEGER DEFAULT 0,
            last_updated INTEGER NOT NULL
        )
    "#).execute(pool).await?;

    // ── Security incidents ──
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS security_incidents (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            entry_point_entity_id TEXT,
            affected_entities TEXT DEFAULT '[]',
            attack_timeline TEXT NOT NULL,
            mitre_ttps TEXT DEFAULT '[]',
            vulnerability TEXT,
            remediation TEXT,
            status TEXT DEFAULT 'open',
            detected_at INTEGER NOT NULL,
            resolved_at INTEGER
        )
    "#).execute(pool).await?;

    // ── Communication policies ──
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS comm_policies (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            name TEXT NOT NULL,
            source_type TEXT,
            dest_type TEXT,
            allowed_intents TEXT NOT NULL,
            max_sessions_per_hour INTEGER,
            require_clearance_match INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            priority INTEGER DEFAULT 100,
            created_at INTEGER NOT NULL
        )
    "#).execute(pool).await?;

    // ── Indexes ──
    for idx in &[
        "CREATE INDEX IF NOT EXISTS idx_entities_org ON entities(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_org ON sessions(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_source ON sessions(source_entity_id)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_chain(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_chain(source_entity_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_chain(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_org ON security_incidents(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status)",
        "CREATE INDEX IF NOT EXISTS idx_policies_org ON comm_policies(org_id)",
    ] {
        sqlx::query(idx).execute(pool).await?;
    }

    tracing::info!("Database migrations complete — 7 tables, 12 indexes");
    Ok(())
}
