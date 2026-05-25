use crate::db::DbPool;

/// Run all database migrations (idempotent).
/// NOTE: These are now also handled by sqlx::migrate! in DbPool::connect().
/// This function is kept for backward compatibility.
#[allow(dead_code)]
pub async fn run(pool: &DbPool) -> anyhow::Result<()> {
    // Enable WAL mode and foreign keys for SQLite only
    if let DbPool::Sqlite(sqlite_pool) = pool {
        sqlx::query("PRAGMA journal_mode=WAL;")
            .execute(sqlite_pool)
            .await?;
        sqlx::query("PRAGMA foreign_keys=ON;")
            .execute(sqlite_pool)
            .await?;
    }

    // ── Core identity registry ──
    let sql = r#"
        CREATE TABLE IF NOT EXISTS organisations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            ollama_endpoint_enc TEXT,
            trust_mode TEXT DEFAULT 'hybrid',
            created_at INTEGER NOT NULL
        )
    "#;
    match pool {
        DbPool::Sqlite(p) => {
            sqlx::query(sql).execute(p).await?;
        }
        DbPool::Postgres(p) => {
            sqlx::query(sql).execute(p).await?;
        }
    }

    // ── Entity registry ──
    let sql = r#"
        CREATE TABLE IF NOT EXISTS entities (
            id TEXT PRIMARY KEY,
            org_id TEXT REFERENCES organisations(id),
            name TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            public_key TEXT NOT NULL,
            department TEXT,
            clearance_level INTEGER DEFAULT 0,
            allowed_intents TEXT,
            trust_score_avg REAL DEFAULT 128,
            session_count INTEGER DEFAULT 0,
            blocked_count INTEGER DEFAULT 0,
            quarantined INTEGER DEFAULT 0,
            last_seen INTEGER,
            enrolled_at INTEGER NOT NULL
        )
    "#;
    match pool {
        DbPool::Sqlite(p) => {
            sqlx::query(sql).execute(p).await?;
        }
        DbPool::Postgres(p) => {
            sqlx::query(sql).execute(p).await?;
        }
    }

    // ── Sessions ──
    let sql = r#"
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
            anomaly_flags TEXT,
            started_at INTEGER NOT NULL,
            ended_at INTEGER,
            close_reason TEXT
        )
    "#;
    match pool {
        DbPool::Sqlite(p) => {
            sqlx::query(sql).execute(p).await?;
        }
        DbPool::Postgres(p) => {
            sqlx::query(sql).execute(p).await?;
        }
    }

    // ── Immutable audit chain ──
    let sql = r#"
        CREATE TABLE IF NOT EXISTS audit_chain (
            id TEXT PRIMARY KEY,
            seq INTEGER,
            org_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_entity_id TEXT,
            session_id TEXT,
            description TEXT NOT NULL,
            metadata TEXT,
            prev_hash TEXT,
            entry_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    "#;
    match pool {
        DbPool::Sqlite(p) => {
            sqlx::query(sql).execute(p).await?;
        }
        DbPool::Postgres(p) => {
            sqlx::query(sql).execute(p).await?;
        }
    }

    // ── Entity baselines ──
    let sql = r#"
        CREATE TABLE IF NOT EXISTS entity_baselines (
            entity_id TEXT PRIMARY KEY,
            avg_sessions_per_hour REAL DEFAULT 0,
            intent_distribution TEXT,
            avg_trust_score REAL DEFAULT 128,
            known_peers TEXT,
            avg_payload_bytes REAL DEFAULT 0,
            normal_hours TEXT,
            learning_complete INTEGER DEFAULT 0,
            sample_count INTEGER DEFAULT 0,
            last_updated INTEGER NOT NULL
        )
    "#;
    match pool {
        DbPool::Sqlite(p) => {
            sqlx::query(sql).execute(p).await?;
        }
        DbPool::Postgres(p) => {
            sqlx::query(sql).execute(p).await?;
        }
    }

    // ── Security incidents ──
    let sql = r#"
        CREATE TABLE IF NOT EXISTS security_incidents (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            summary TEXT,
            entry_point_entity_id TEXT,
            affected_entities TEXT,
            attack_timeline TEXT NOT NULL,
            mitre_ttps TEXT,
            vulnerability TEXT,
            remediation TEXT,
            status TEXT DEFAULT 'open',
            confidence REAL DEFAULT 0,
            investigation_steps INTEGER DEFAULT 0,
            detected_at INTEGER NOT NULL,
            resolved_at INTEGER
        )
    "#;
    match pool {
        DbPool::Sqlite(p) => {
            sqlx::query(sql).execute(p).await?;
        }
        DbPool::Postgres(p) => {
            sqlx::query(sql).execute(p).await?;
        }
    }

    // ── Anomalies ──
    let sql = r#"
        CREATE TABLE IF NOT EXISTS anomalies (
            id TEXT PRIMARY KEY,
            entity_id TEXT NOT NULL,
            org_id TEXT NOT NULL,
            anomaly_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            confidence REAL NOT NULL,
            session_id TEXT,
            metadata TEXT,
            detected_at INTEGER NOT NULL
        )
    "#;
    match pool {
        DbPool::Sqlite(p) => {
            sqlx::query(sql).execute(p).await?;
        }
        DbPool::Postgres(p) => {
            sqlx::query(sql).execute(p).await?;
        }
    }

    // ── Communication policies ──
    let sql = r#"
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
    "#;
    match pool {
        DbPool::Sqlite(p) => {
            sqlx::query(sql).execute(p).await?;
        }
        DbPool::Postgres(p) => {
            sqlx::query(sql).execute(p).await?;
        }
    }

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
        match pool {
            DbPool::Sqlite(p) => {
                sqlx::query(idx).execute(p).await?;
            }
            DbPool::Postgres(p) => {
                sqlx::query(idx).execute(p).await?;
            }
        }
    }

    tracing::info!("Database migrations complete — 7 tables, 12 indexes");
    Ok(())
}
