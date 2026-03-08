pub async fn run(pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
    sqlx::query("PRAGMA journal_mode=WAL;")
        .execute(pool)
        .await?;
    sqlx::query("PRAGMA foreign_keys=ON;").execute(pool).await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL, industry TEXT,
        gemini_api_key_enc TEXT, claude_api_key_enc TEXT, openai_api_key_enc TEXT,
        ai_provider TEXT NOT NULL DEFAULT 'gemini',
        ai_model TEXT NOT NULL DEFAULT 'gemini-2.5-flash-preview-05-20',
        trust_mode TEXT NOT NULL DEFAULT 'hybrid',
        created_at INTEGER NOT NULL, last_login INTEGER
    )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS server_nodes (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        name TEXT NOT NULL, listen_address TEXT NOT NULL DEFAULT '0.0.0.0',
        listen_port INTEGER NOT NULL DEFAULT 9999,
        entity_id TEXT NOT NULL, public_key TEXT NOT NULL, private_key_path TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'offline', client_count INTEGER NOT NULL DEFAULT 0,
        session_count INTEGER NOT NULL DEFAULT 0, last_seen INTEGER, created_at INTEGER NOT NULL,
        UNIQUE(org_id, name)
    )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS client_nodes (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        name TEXT NOT NULL, entity_id TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL,
        private_key_path TEXT NOT NULL,
        allowed_intents TEXT NOT NULL DEFAULT '["ModelInference","DataSync"]',
        trust_score INTEGER NOT NULL DEFAULT 128, session_count INTEGER NOT NULL DEFAULT 0,
        blocked_count INTEGER NOT NULL DEFAULT 0, last_seen INTEGER, created_at INTEGER NOT NULL,
        UNIQUE(org_id, name)
    )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL, server_node_id TEXT NOT NULL,
        client_node_id TEXT, client_entity_id TEXT NOT NULL,
        client_ip TEXT NOT NULL, client_port INTEGER NOT NULL,
        intent TEXT NOT NULL, trust_score INTEGER NOT NULL, verdict TEXT NOT NULL,
        ai_provider TEXT, ai_latency_ms INTEGER, ai_reasoning TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        bytes_tx INTEGER NOT NULL DEFAULT 0, bytes_rx INTEGER NOT NULL DEFAULT 0,
        started_at INTEGER NOT NULL, ended_at INTEGER, close_reason TEXT
    )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY, org_id TEXT, event_type TEXT NOT NULL, severity TEXT NOT NULL,
        source_ip TEXT, entity_id TEXT, session_id TEXT,
        description TEXT NOT NULL, metadata TEXT, created_at INTEGER NOT NULL
    )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS federated_orgs (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        remote_org_id TEXT NOT NULL,
        remote_org_name TEXT NOT NULL,
        remote_root_pubkey TEXT NOT NULL,
        federation_level TEXT NOT NULL DEFAULT 'RESTRICTED',
        allowed_intents TEXT NOT NULL DEFAULT '["ModelInference"]',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        UNIQUE(org_id, remote_org_id)
    )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS federated_sessions (
        session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
        local_org_id TEXT NOT NULL,
        remote_org_id TEXT NOT NULL,
        ftt_id TEXT NOT NULL,
        federation_level TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )"#,
    )
    .execute(pool)
    .await?;

    // Indexes
    for idx in &[
        "CREATE INDEX IF NOT EXISTS idx_sessions_org ON sessions(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_events_org ON audit_events(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_type ON audit_events(event_type)",
        "CREATE INDEX IF NOT EXISTS idx_events_time ON audit_events(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_fed_orgs_remote ON federated_orgs(remote_org_id)",
        "CREATE INDEX IF NOT EXISTS idx_fed_sessions_remote ON federated_sessions(remote_org_id)",
    ] {
        sqlx::query(idx).execute(pool).await?;
    }

    tracing::info!("Database migrations complete");
    Ok(())
}
