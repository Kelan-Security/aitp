use crate::db::{models::*, DbPool};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ═══════════════════════════════════════════════════════════════
// MACROS: To support both Postgres ($1) and SQLite (?) without duplicating every line
// ═══════════════════════════════════════════════════════════════

#[allow(dead_code)]
impl DbPool {
    // ═══ Organisations ═══

    pub async fn create_org(&self, org: Organisation) -> Result<(), sqlx::Error> {
        let sql_pg = "INSERT INTO organisations (id, name, email, password_hash, gemini_api_key_enc, trust_mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)";
        let sql_sq = "INSERT INTO organisations (id, name, email, password_hash, gemini_api_key_enc, trust_mode, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
        
        match self {
            DbPool::Postgres(p) => {
                sqlx::query(sql_pg)
                    .bind(&org.id).bind(&org.name).bind(&org.email)
                    .bind(&org.password_hash).bind(&org.gemini_api_key_enc)
                    .bind(&org.trust_mode).bind(org.created_at)
                    .execute(p).await?;
            }
            DbPool::Sqlite(p) => {
                sqlx::query(sql_sq)
                    .bind(&org.id).bind(&org.name).bind(&org.email)
                    .bind(&org.password_hash).bind(&org.gemini_api_key_enc)
                    .bind(&org.trust_mode).bind(org.created_at)
                    .execute(p).await?;
            }
        }
        Ok(())
    }

    pub async fn get_org_by_email(&self, email: &str) -> Result<Organisation, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => sqlx::query_as("SELECT * FROM organisations WHERE email = $1").bind(email).fetch_one(p).await,
            DbPool::Sqlite(p) => sqlx::query_as("SELECT * FROM organisations WHERE email = ?").bind(email).fetch_one(p).await,
        }
    }

    pub async fn get_org_by_id(&self, id: &str) -> Result<Organisation, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => sqlx::query_as("SELECT * FROM organisations WHERE id = $1").bind(id).fetch_one(p).await,
            DbPool::Sqlite(p) => sqlx::query_as("SELECT * FROM organisations WHERE id = ?").bind(id).fetch_one(p).await,
        }
    }

    pub async fn update_org_ai_config(
        &self,
        id: &str,
        api_key_enc: Option<&str>,
        trust_mode: &str,
    ) -> Result<(), sqlx::Error> {
        if let Some(key) = api_key_enc {
            match self {
                DbPool::Postgres(p) => {
                    sqlx::query("UPDATE organisations SET gemini_api_key_enc = $1, trust_mode = $2 WHERE id = $3")
                        .bind(key).bind(trust_mode).bind(id).execute(p).await?;
                }
                DbPool::Sqlite(p) => {
                    sqlx::query("UPDATE organisations SET gemini_api_key_enc = ?, trust_mode = ? WHERE id = ?")
                        .bind(key).bind(trust_mode).bind(id).execute(p).await?;
                }
            }
        } else {
            match self {
                DbPool::Postgres(p) => {
                    sqlx::query("UPDATE organisations SET trust_mode = $1 WHERE id = $2")
                        .bind(trust_mode).bind(id).execute(p).await?;
                }
                DbPool::Sqlite(p) => {
                    sqlx::query("UPDATE organisations SET trust_mode = ? WHERE id = ?")
                        .bind(trust_mode).bind(id).execute(p).await?;
                }
            }
        }
        Ok(())
    }

    // ═══ Entities ═══

    pub async fn create_entity(&self, mut e: Entity) -> Result<(), sqlx::Error> {
        // Apply missing default JSONs
        if e.allowed_intents.is_empty() {
            e.allowed_intents = r#"["ModelInference","Heartbeat","DataSync"]"#.to_string();
        }
        
        let sql_pg = "INSERT INTO entities (id, org_id, name, entity_type, public_key, department, clearance_level, allowed_intents, trust_score_avg, session_count, blocked_count, quarantined, enrolled_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
        let sql_sq = "INSERT INTO entities (id, org_id, name, entity_type, public_key, department, clearance_level, allowed_intents, trust_score_avg, session_count, blocked_count, quarantined, enrolled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        match self {
            DbPool::Postgres(p) => {
                sqlx::query(sql_pg)
                    .bind(&e.id).bind(&e.org_id).bind(&e.name).bind(&e.entity_type)
                    .bind(&e.public_key).bind(&e.department).bind(e.clearance_level)
                    .bind(&e.allowed_intents).bind(e.trust_score_avg)
                    .bind(e.session_count).bind(e.blocked_count).bind(e.quarantined)
                    .bind(e.enrolled_at).execute(p).await?;
            }
            DbPool::Sqlite(p) => {
                sqlx::query(sql_sq)
                    .bind(&e.id).bind(&e.org_id).bind(&e.name).bind(&e.entity_type)
                    .bind(&e.public_key).bind(&e.department).bind(e.clearance_level)
                    .bind(&e.allowed_intents).bind(e.trust_score_avg)
                    .bind(e.session_count).bind(e.blocked_count).bind(e.quarantined)
                    .bind(e.enrolled_at).execute(p).await?;
            }
        }
        Ok(())
    }

    pub async fn get_entities(&self, org_id: &str) -> Result<Vec<Entity>, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => sqlx::query_as("SELECT * FROM entities WHERE org_id = $1 ORDER BY enrolled_at DESC").bind(org_id).fetch_all(p).await,
            DbPool::Sqlite(p) => sqlx::query_as("SELECT * FROM entities WHERE org_id = ? ORDER BY enrolled_at DESC").bind(org_id).fetch_all(p).await,
        }
    }

    pub async fn get_entity(&self, id: &str) -> Result<Entity, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => sqlx::query_as("SELECT * FROM entities WHERE id = $1").bind(id).fetch_one(p).await,
            DbPool::Sqlite(p) => sqlx::query_as("SELECT * FROM entities WHERE id = ?").bind(id).fetch_one(p).await,
        }
    }

    pub async fn quarantine_entity(&self, id: &str) -> Result<u64, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => {
                let r = sqlx::query("UPDATE entities SET quarantined = 1 WHERE id = $1").bind(id).execute(p).await?;
                Ok(r.rows_affected())
            }
            DbPool::Sqlite(p) => {
                let r = sqlx::query("UPDATE entities SET quarantined = 1 WHERE id = ?").bind(id).execute(p).await?;
                Ok(r.rows_affected())
            }
        }
    }

    pub async fn release_entity(&self, id: &str) -> Result<u64, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => {
                let r = sqlx::query("UPDATE entities SET quarantined = 0 WHERE id = $1").bind(id).execute(p).await?;
                Ok(r.rows_affected())
            }
            DbPool::Sqlite(p) => {
                let r = sqlx::query("UPDATE entities SET quarantined = 0 WHERE id = ?").bind(id).execute(p).await?;
                Ok(r.rows_affected())
            }
        }
    }

    pub async fn delete_entity(&self, org_id: &str, id: &str) -> Result<u64, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => {
                let r = sqlx::query("DELETE FROM entities WHERE id = $1 AND org_id = $2").bind(id).bind(org_id).execute(p).await?;
                Ok(r.rows_affected())
            }
            DbPool::Sqlite(p) => {
                let r = sqlx::query("DELETE FROM entities WHERE id = ? AND org_id = ?").bind(id).bind(org_id).execute(p).await?;
                Ok(r.rows_affected())
            }
        }
    }

    pub async fn update_entity_last_seen(&self, id: &str) -> Result<(), sqlx::Error> {
        match self {
            DbPool::Postgres(p) => { sqlx::query("UPDATE entities SET last_seen = $1 WHERE id = $2").bind(now()).bind(id).execute(p).await?; }
            DbPool::Sqlite(p) => { sqlx::query("UPDATE entities SET last_seen = ? WHERE id = ?").bind(now()).bind(id).execute(p).await?; }
        }
        Ok(())
    }

    pub async fn increment_entity_session_count(&self, id: &str) -> Result<(), sqlx::Error> {
        match self {
            DbPool::Postgres(p) => { sqlx::query("UPDATE entities SET session_count = session_count + 1 WHERE id = $1").bind(id).execute(p).await?; }
            DbPool::Sqlite(p) => { sqlx::query("UPDATE entities SET session_count = session_count + 1 WHERE id = ?").bind(id).execute(p).await?; }
        }
        Ok(())
    }

    pub async fn increment_entity_blocked_count(&self, id: &str) -> Result<(), sqlx::Error> {
        match self {
            DbPool::Postgres(p) => { sqlx::query("UPDATE entities SET blocked_count = blocked_count + 1 WHERE id = $1").bind(id).execute(p).await?; }
            DbPool::Sqlite(p) => { sqlx::query("UPDATE entities SET blocked_count = blocked_count + 1 WHERE id = ?").bind(id).execute(p).await?; }
        }
        Ok(())
    }

    // ═══ Sessions ═══

    pub async fn create_session(&self, mut s: Session) -> Result<(), sqlx::Error> {
        if s.anomaly_flags.is_empty() {
            s.anomaly_flags = "[]".to_string();
        }
        
        let sql_pg = "INSERT INTO sessions (id, org_id, source_entity_id, dest_entity_id, intent, trust_score, verdict, ai_reasoning, ai_latency_ms, status, bytes_tx, bytes_rx, anomaly_flags, started_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)";
        let sql_sq = "INSERT INTO sessions (id, org_id, source_entity_id, dest_entity_id, intent, trust_score, verdict, ai_reasoning, ai_latency_ms, status, bytes_tx, bytes_rx, anomaly_flags, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        match self {
            DbPool::Postgres(p) => {
                sqlx::query(sql_pg)
                    .bind(&s.id).bind(&s.org_id).bind(&s.source_entity_id).bind(&s.dest_entity_id)
                    .bind(&s.intent).bind(s.trust_score).bind(&s.verdict)
                    .bind(&s.ai_reasoning).bind(s.ai_latency_ms)
                    .bind(&s.status).bind(s.bytes_tx).bind(s.bytes_rx)
                    .bind(&s.anomaly_flags).bind(s.started_at).execute(p).await?;
            }
            DbPool::Sqlite(p) => {
                sqlx::query(sql_sq)
                    .bind(&s.id).bind(&s.org_id).bind(&s.source_entity_id).bind(&s.dest_entity_id)
                    .bind(&s.intent).bind(s.trust_score).bind(&s.verdict)
                    .bind(&s.ai_reasoning).bind(s.ai_latency_ms)
                    .bind(&s.status).bind(s.bytes_tx).bind(s.bytes_rx)
                    .bind(&s.anomaly_flags).bind(s.started_at).execute(p).await?;
            }
        }
        Ok(())
    }

    pub async fn get_sessions(
        &self,
        org_id: &str,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<Session>, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => {
                if let Some(st) = status {
                    sqlx::query_as("SELECT * FROM sessions WHERE org_id = $1 AND status = $2 ORDER BY started_at DESC LIMIT $3")
                        .bind(org_id).bind(st).bind(limit).fetch_all(p).await
                } else {
                    sqlx::query_as("SELECT * FROM sessions WHERE org_id = $1 ORDER BY started_at DESC LIMIT $2")
                        .bind(org_id).bind(limit).fetch_all(p).await
                }
            }
            DbPool::Sqlite(p) => {
                if let Some(st) = status {
                    sqlx::query_as("SELECT * FROM sessions WHERE org_id = ? AND status = ? ORDER BY started_at DESC LIMIT ?")
                        .bind(org_id).bind(st).bind(limit).fetch_all(p).await
                } else {
                    sqlx::query_as("SELECT * FROM sessions WHERE org_id = ? ORDER BY started_at DESC LIMIT ?")
                        .bind(org_id).bind(limit).fetch_all(p).await
                }
            }
        }
    }

    pub async fn get_session(&self, id: &str) -> Result<Session, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => sqlx::query_as("SELECT * FROM sessions WHERE id = $1").bind(id).fetch_one(p).await,
            DbPool::Sqlite(p) => sqlx::query_as("SELECT * FROM sessions WHERE id = ?").bind(id).fetch_one(p).await,
        }
    }

    pub async fn revoke_session(&self, id: &str) -> Result<u64, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => {
                let r = sqlx::query("UPDATE sessions SET status = 'revoked', ended_at = $1, close_reason = 'manual_revoke' WHERE id = $2 AND status = 'active'")
                    .bind(now()).bind(id).execute(p).await?;
                Ok(r.rows_affected())
            }
            DbPool::Sqlite(p) => {
                let r = sqlx::query("UPDATE sessions SET status = 'revoked', ended_at = ?, close_reason = 'manual_revoke' WHERE id = ? AND status = 'active'")
                    .bind(now()).bind(id).execute(p).await?;
                Ok(r.rows_affected())
            }
        }
    }

    pub async fn close_session(
        &self,
        id: &str,
        reason: &str,
        tx: i64,
        rx: i64,
    ) -> Result<(), sqlx::Error> {
        match self {
            DbPool::Postgres(p) => {
                sqlx::query("UPDATE sessions SET status = 'closed', ended_at = $1, close_reason = $2, bytes_tx = bytes_tx + $3, bytes_rx = bytes_rx + $4 WHERE id = $5 AND status = 'active'")
                    .bind(now()).bind(reason).bind(tx).bind(rx).bind(id).execute(p).await?;
            }
            DbPool::Sqlite(p) => {
                sqlx::query("UPDATE sessions SET status = 'closed', ended_at = ?, close_reason = ?, bytes_tx = bytes_tx + ?, bytes_rx = bytes_rx + ? WHERE id = ? AND status = 'active'")
                    .bind(now()).bind(reason).bind(tx).bind(rx).bind(id).execute(p).await?;
            }
        }
        Ok(())
    }

    pub async fn expire_old_sessions(&self, max_age_secs: i64) -> Result<u64, sqlx::Error> {
        let cutoff = now() - max_age_secs;
        match self {
            DbPool::Postgres(p) => {
                let r = sqlx::query("UPDATE sessions SET status = 'closed', ended_at = $1, close_reason = 'expired' WHERE status = 'active' AND started_at < $2")
                    .bind(now()).bind(cutoff).execute(p).await?;
                Ok(r.rows_affected())
            }
            DbPool::Sqlite(p) => {
                let r = sqlx::query("UPDATE sessions SET status = 'closed', ended_at = ?, close_reason = 'expired' WHERE status = 'active' AND started_at < ?")
                    .bind(now()).bind(cutoff).execute(p).await?;
                Ok(r.rows_affected())
            }
        }
    }

    // ═══ Audit Chain ═══

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_audit(
        &self,
        org_id: &str,
        event_type: &str,
        severity: &str,
        entity_id: Option<&str>,
        session_id: Option<&str>,
        description: &str,
        metadata: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let entry_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(format!(
                "{}:{}:{}:{}",
                org_id,
                event_type,
                description,
                now()
            ));
            hex::encode(hasher.finalize())
        };
        
        let meta = metadata.unwrap_or("{}");
        let new_seq_id = new_id(); // Use UUID for audit chain ID since we removed AUTOINCREMENT

        let sql_pg = "INSERT INTO audit_chain (id, org_id, event_type, severity, source_entity_id, session_id, description, metadata, prev_hash, entry_hash, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '', $9, $10)";
        let sql_sq = "INSERT INTO audit_chain (id, org_id, event_type, severity, source_entity_id, session_id, description, metadata, prev_hash, entry_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)";
        
        match self {
            DbPool::Postgres(p) => {
                sqlx::query(sql_pg)
                    .bind(&new_seq_id).bind(org_id).bind(event_type).bind(severity)
                    .bind(entity_id).bind(session_id).bind(description)
                    .bind(meta).bind(&entry_hash).bind(now()).execute(p).await?;
            }
            DbPool::Sqlite(p) => {
                sqlx::query(sql_sq)
                    .bind(&new_seq_id).bind(org_id).bind(event_type).bind(severity)
                    .bind(entity_id).bind(session_id).bind(description)
                    .bind(meta).bind(&entry_hash).bind(now()).execute(p).await?;
            }
        }
        Ok(())
    }

    pub async fn get_recent_audit(
        &self,
        org_id: &str,
        limit: i64,
    ) -> Result<Vec<AuditEntry>, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => sqlx::query_as("SELECT * FROM audit_chain WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2").bind(org_id).bind(limit).fetch_all(p).await,
            DbPool::Sqlite(p) => sqlx::query_as("SELECT * FROM audit_chain WHERE org_id = ? ORDER BY created_at DESC LIMIT ?").bind(org_id).bind(limit).fetch_all(p).await,
        }
    }

    // ═══ Security Incidents ═══

    pub async fn get_incidents(
        &self,
        org_id: &str,
    ) -> Result<Vec<SecurityIncidentRow>, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => sqlx::query_as("SELECT * FROM security_incidents WHERE org_id = $1 OR org_id = 'system' ORDER BY detected_at DESC").bind(org_id).fetch_all(p).await,
            DbPool::Sqlite(p) => sqlx::query_as("SELECT * FROM security_incidents WHERE org_id = ? OR org_id = 'system' ORDER BY detected_at DESC").bind(org_id).fetch_all(p).await,
        }
    }

    pub async fn get_incident(&self, id: &str) -> Result<SecurityIncidentRow, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => sqlx::query_as("SELECT * FROM security_incidents WHERE id = $1").bind(id).fetch_one(p).await,
            DbPool::Sqlite(p) => sqlx::query_as("SELECT * FROM security_incidents WHERE id = ?").bind(id).fetch_one(p).await,
        }
    }

    pub async fn resolve_incident(&self, id: &str) -> Result<u64, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => {
                let r = sqlx::query("UPDATE security_incidents SET status = 'resolved', resolved_at = $1 WHERE id = $2").bind(now()).bind(id).execute(p).await?;
                Ok(r.rows_affected())
            }
            DbPool::Sqlite(p) => {
                let r = sqlx::query("UPDATE security_incidents SET status = 'resolved', resolved_at = ? WHERE id = ?").bind(now()).bind(id).execute(p).await?;
                Ok(r.rows_affected())
            }
        }
    }

    // ═══ Policies ═══

    pub async fn get_policies(&self, org_id: &str) -> Result<Vec<CommPolicy>, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => sqlx::query_as("SELECT * FROM comm_policies WHERE org_id = $1 ORDER BY priority ASC").bind(org_id).fetch_all(p).await,
            DbPool::Sqlite(p) => sqlx::query_as("SELECT * FROM comm_policies WHERE org_id = ? ORDER BY priority ASC").bind(org_id).fetch_all(p).await,
        }
    }

    pub async fn create_policy(&self, p: CommPolicy) -> Result<(), sqlx::Error> {
        let sql_pg = "INSERT INTO comm_policies (id, org_id, name, source_type, dest_type, allowed_intents, max_sessions_per_hour, require_clearance_match, enabled, priority, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
        let sql_sq = "INSERT INTO comm_policies (id, org_id, name, source_type, dest_type, allowed_intents, max_sessions_per_hour, require_clearance_match, enabled, priority, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        match self {
            DbPool::Postgres(pool) => {
                sqlx::query(sql_pg)
                    .bind(&p.id).bind(&p.org_id).bind(&p.name)
                    .bind(&p.source_type).bind(&p.dest_type)
                    .bind(&p.allowed_intents).bind(p.max_sessions_per_hour)
                    .bind(p.require_clearance_match).bind(p.enabled)
                    .bind(p.priority).bind(p.created_at).execute(pool).await?;
            }
            DbPool::Sqlite(pool) => {
                sqlx::query(sql_sq)
                    .bind(&p.id).bind(&p.org_id).bind(&p.name)
                    .bind(&p.source_type).bind(&p.dest_type)
                    .bind(&p.allowed_intents).bind(p.max_sessions_per_hour)
                    .bind(p.require_clearance_match).bind(p.enabled)
                    .bind(p.priority).bind(p.created_at).execute(pool).await?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_policy(
        &self,
        id: &str,
        org_id: &str,
        name: Option<&str>,
        source_type: Option<&str>,
        dest_type: Option<&str>,
        allowed_intents: Option<&str>,
        max_sph: Option<i64>,
        clearance: Option<i64>,
        enabled: Option<i64>,
        priority: Option<i64>,
    ) -> Result<u64, sqlx::Error> {
        let mut sets = Vec::new();
        let mut vals: Vec<String> = Vec::new();

        if let Some(v) = name { sets.push("name"); vals.push(v.to_string()); }
        if let Some(v) = source_type { sets.push("source_type"); vals.push(v.to_string()); }
        if let Some(v) = dest_type { sets.push("dest_type"); vals.push(v.to_string()); }
        if let Some(v) = allowed_intents { sets.push("allowed_intents"); vals.push(v.to_string()); }
        if let Some(v) = max_sph { sets.push("max_sessions_per_hour"); vals.push(v.to_string()); }
        if let Some(v) = clearance { sets.push("require_clearance_match"); vals.push(v.to_string()); }
        if let Some(v) = enabled { sets.push("enabled"); vals.push(v.to_string()); }
        if let Some(v) = priority { sets.push("priority"); vals.push(v.to_string()); }

        if sets.is_empty() { return Ok(0); }

        match self {
            DbPool::Postgres(p) => {
                let set_clauses = sets.iter().enumerate()
                    .map(|(i, col)| format!("{} = ${}", col, i + 1))
                    .collect::<Vec<_>>().join(", ");
                let sql = format!("UPDATE comm_policies SET {} WHERE id = ${} AND org_id = ${}", set_clauses, sets.len() + 1, sets.len() + 2);
                let mut q = sqlx::query(&sql);
                for v in &vals { q = q.bind(v); }
                q = q.bind(id).bind(org_id);
                let r = q.execute(p).await?;
                Ok(r.rows_affected())
            }
            DbPool::Sqlite(p) => {
                let set_clauses = sets.iter()
                    .map(|col| format!("{} = ?", col))
                    .collect::<Vec<_>>().join(", ");
                let sql = format!("UPDATE comm_policies SET {} WHERE id = ? AND org_id = ?", set_clauses);
                let mut q = sqlx::query(&sql);
                for v in &vals { q = q.bind(v); }
                q = q.bind(id).bind(org_id);
                let r = q.execute(p).await?;
                Ok(r.rows_affected())
            }
        }
    }

    pub async fn delete_policy(&self, id: &str, org_id: &str) -> Result<u64, sqlx::Error> {
        match self {
            DbPool::Postgres(p) => {
                let r = sqlx::query("DELETE FROM comm_policies WHERE id = $1 AND org_id = $2").bind(id).bind(org_id).execute(p).await?;
                Ok(r.rows_affected())
            }
            DbPool::Sqlite(p) => {
                let r = sqlx::query("DELETE FROM comm_policies WHERE id = ? AND org_id = ?").bind(id).bind(org_id).execute(p).await?;
                Ok(r.rows_affected())
            }
        }
    }

    // ═══ Stats ═══

    pub async fn get_stats(&self, uptime_secs: u64) -> Result<StatsResp, sqlx::Error> {
        let active_sessions: i64 = match self {
            DbPool::Postgres(p) => sqlx::query_scalar("SELECT count(*)::bigint FROM sessions WHERE status = 'active'").fetch_one(p).await.unwrap_or(0),
            DbPool::Sqlite(p) => sqlx::query_scalar("SELECT count(*) FROM sessions WHERE status = 'active'").fetch_one(p).await.unwrap_or(0),
        };

        let avg_trust: Option<f64> = match self {
            DbPool::Postgres(p) => sqlx::query_scalar("SELECT avg(trust_score)::float8 FROM sessions").fetch_one(p).await.unwrap_or(None),
            DbPool::Sqlite(p) => sqlx::query_scalar("SELECT avg(trust_score) FROM sessions").fetch_one(p).await.unwrap_or(None),
        };

        let today = now() - 86400;
        
        let blocked_today: i64 = match self {
            DbPool::Postgres(p) => sqlx::query_scalar("SELECT count(*)::bigint FROM sessions WHERE verdict = 'Deny' AND started_at >= $1").bind(today).fetch_one(p).await.unwrap_or(0),
            DbPool::Sqlite(p) => sqlx::query_scalar("SELECT count(*) FROM sessions WHERE verdict = 'Deny' AND started_at >= ?").bind(today).fetch_one(p).await.unwrap_or(0),
        };

        let ai_calls: i64 = match self {
            DbPool::Postgres(p) => sqlx::query_scalar("SELECT count(*)::bigint FROM sessions WHERE ai_latency_ms IS NOT NULL AND started_at >= $1").bind(today).fetch_one(p).await.unwrap_or(0),
            DbPool::Sqlite(p) => sqlx::query_scalar("SELECT count(*) FROM sessions WHERE ai_latency_ms IS NOT NULL AND started_at >= ?").bind(today).fetch_one(p).await.unwrap_or(0),
        };

        let entities_online: i64 = match self {
            DbPool::Postgres(p) => sqlx::query_scalar("SELECT count(*)::bigint FROM entities WHERE last_seen > $1 AND quarantined = 0").bind(now() - 300).fetch_one(p).await.unwrap_or(0),
            DbPool::Sqlite(p) => sqlx::query_scalar("SELECT count(*) FROM entities WHERE last_seen > ? AND quarantined = 0").bind(now() - 300).fetch_one(p).await.unwrap_or(0),
        };

        let threats_today: i64 = match self {
            DbPool::Postgres(p) => sqlx::query_scalar("SELECT count(*)::bigint FROM security_incidents WHERE detected_at >= $1").bind(today).fetch_one(p).await.unwrap_or(0),
            DbPool::Sqlite(p) => sqlx::query_scalar("SELECT count(*) FROM security_incidents WHERE detected_at >= ?").bind(today).fetch_one(p).await.unwrap_or(0),
        };

        Ok(StatsResp {
            active_sessions,
            blocked_today,
            ai_calls,
            avg_trust,
            entities_online,
            threats_detected_today: threats_today,
            uptime_secs,
        })
    }
}
