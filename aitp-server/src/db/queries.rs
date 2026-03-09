use crate::db::{models::*, DbPool};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[allow(dead_code)]
impl DbPool {
    // ═══ Organisations ═══

    pub async fn create_org(&self, org: Organisation) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO organisations (id, name, email, password_hash, gemini_api_key_enc, trust_mode, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&org.id).bind(&org.name).bind(&org.email)
        .bind(&org.password_hash).bind(&org.gemini_api_key_enc)
        .bind(&org.trust_mode).bind(org.created_at)
        .execute(self.inner()).await?;
        Ok(())
    }

    pub async fn get_org_by_email(&self, email: &str) -> Result<Organisation, sqlx::Error> {
        sqlx::query_as("SELECT * FROM organisations WHERE email = ?")
            .bind(email)
            .fetch_one(self.inner())
            .await
    }

    pub async fn get_org_by_id(&self, id: &str) -> Result<Organisation, sqlx::Error> {
        sqlx::query_as("SELECT * FROM organisations WHERE id = ?")
            .bind(id)
            .fetch_one(self.inner())
            .await
    }

    pub async fn update_org_ai_config(
        &self,
        id: &str,
        api_key_enc: Option<&str>,
        trust_mode: &str,
    ) -> Result<(), sqlx::Error> {
        if let Some(key) = api_key_enc {
            sqlx::query(
                "UPDATE organisations SET gemini_api_key_enc = ?, trust_mode = ? WHERE id = ?",
            )
            .bind(key)
            .bind(trust_mode)
            .bind(id)
            .execute(self.inner())
            .await?;
        } else {
            sqlx::query("UPDATE organisations SET trust_mode = ? WHERE id = ?")
                .bind(trust_mode)
                .bind(id)
                .execute(self.inner())
                .await?;
        }
        Ok(())
    }

    // ═══ Entities ═══

    pub async fn create_entity(&self, e: Entity) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO entities (id, org_id, name, entity_type, public_key, department, clearance_level, allowed_intents, trust_score_avg, session_count, blocked_count, quarantined, enrolled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&e.id).bind(&e.org_id).bind(&e.name).bind(&e.entity_type)
        .bind(&e.public_key).bind(&e.department).bind(e.clearance_level)
        .bind(&e.allowed_intents).bind(e.trust_score_avg)
        .bind(e.session_count).bind(e.blocked_count).bind(e.quarantined)
        .bind(e.enrolled_at)
        .execute(self.inner()).await?;
        Ok(())
    }

    pub async fn get_entities(&self, org_id: &str) -> Result<Vec<Entity>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM entities WHERE org_id = ? ORDER BY enrolled_at DESC")
            .bind(org_id)
            .fetch_all(self.inner())
            .await
    }

    pub async fn get_entity(&self, id: &str) -> Result<Entity, sqlx::Error> {
        sqlx::query_as("SELECT * FROM entities WHERE id = ?")
            .bind(id)
            .fetch_one(self.inner())
            .await
    }

    pub async fn quarantine_entity(&self, id: &str) -> Result<u64, sqlx::Error> {
        let r = sqlx::query("UPDATE entities SET quarantined = 1 WHERE id = ?")
            .bind(id)
            .execute(self.inner())
            .await?;
        Ok(r.rows_affected())
    }

    pub async fn release_entity(&self, id: &str) -> Result<u64, sqlx::Error> {
        let r = sqlx::query("UPDATE entities SET quarantined = 0 WHERE id = ?")
            .bind(id)
            .execute(self.inner())
            .await?;
        Ok(r.rows_affected())
    }

    pub async fn delete_entity(&self, org_id: &str, id: &str) -> Result<u64, sqlx::Error> {
        let r = sqlx::query("DELETE FROM entities WHERE id = ? AND org_id = ?")
            .bind(id)
            .bind(org_id)
            .execute(self.inner())
            .await?;
        Ok(r.rows_affected())
    }

    pub async fn update_entity_last_seen(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE entities SET last_seen = ? WHERE id = ?")
            .bind(now())
            .bind(id)
            .execute(self.inner())
            .await?;
        Ok(())
    }

    pub async fn increment_entity_session_count(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE entities SET session_count = session_count + 1 WHERE id = ?")
            .bind(id)
            .execute(self.inner())
            .await?;
        Ok(())
    }

    pub async fn increment_entity_blocked_count(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE entities SET blocked_count = blocked_count + 1 WHERE id = ?")
            .bind(id)
            .execute(self.inner())
            .await?;
        Ok(())
    }

    // ═══ Sessions ═══

    pub async fn create_session(&self, s: Session) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO sessions (id, org_id, source_entity_id, dest_entity_id, intent, trust_score, verdict, ai_reasoning, ai_latency_ms, status, bytes_tx, bytes_rx, anomaly_flags, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&s.id).bind(&s.org_id).bind(&s.source_entity_id).bind(&s.dest_entity_id)
        .bind(&s.intent).bind(s.trust_score).bind(&s.verdict)
        .bind(&s.ai_reasoning).bind(s.ai_latency_ms)
        .bind(&s.status).bind(s.bytes_tx).bind(s.bytes_rx)
        .bind(&s.anomaly_flags).bind(s.started_at)
        .execute(self.inner()).await?;
        Ok(())
    }

    pub async fn get_sessions(
        &self,
        org_id: &str,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<Session>, sqlx::Error> {
        if let Some(st) = status {
            sqlx::query_as("SELECT * FROM sessions WHERE org_id = ? AND status = ? ORDER BY started_at DESC LIMIT ?")
                .bind(org_id).bind(st).bind(limit)
                .fetch_all(self.inner()).await
        } else {
            sqlx::query_as(
                "SELECT * FROM sessions WHERE org_id = ? ORDER BY started_at DESC LIMIT ?",
            )
            .bind(org_id)
            .bind(limit)
            .fetch_all(self.inner())
            .await
        }
    }

    pub async fn get_session(&self, id: &str) -> Result<Session, sqlx::Error> {
        sqlx::query_as("SELECT * FROM sessions WHERE id = ?")
            .bind(id)
            .fetch_one(self.inner())
            .await
    }

    pub async fn revoke_session(&self, id: &str) -> Result<u64, sqlx::Error> {
        let r = sqlx::query("UPDATE sessions SET status = 'revoked', ended_at = ?, close_reason = 'manual_revoke' WHERE id = ? AND status = 'active'")
            .bind(now()).bind(id).execute(self.inner()).await?;
        Ok(r.rows_affected())
    }

    pub async fn close_session(
        &self,
        id: &str,
        reason: &str,
        tx: i64,
        rx: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sessions SET status = 'closed', ended_at = ?, close_reason = ?, bytes_tx = bytes_tx + ?, bytes_rx = bytes_rx + ? WHERE id = ? AND status = 'active'")
            .bind(now()).bind(reason).bind(tx).bind(rx).bind(id)
            .execute(self.inner()).await?;
        Ok(())
    }

    pub async fn expire_old_sessions(&self, max_age_secs: i64) -> Result<u64, sqlx::Error> {
        let cutoff = now() - max_age_secs;
        let r = sqlx::query("UPDATE sessions SET status = 'closed', ended_at = ?, close_reason = 'expired' WHERE status = 'active' AND started_at < ?")
            .bind(now()).bind(cutoff).execute(self.inner()).await?;
        Ok(r.rows_affected())
    }

    // ═══ Audit Chain ═══

    pub async fn insert_audit(
        &self,
        org_id: &str,
        event_type: &str,
        severity: &str,
        entity_id: Option<&str>,
        session_id: Option<&str>,
        description: &str,
        metadata: &str,
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
        sqlx::query(
            "INSERT INTO audit_chain (org_id, event_type, severity, source_entity_id, session_id, description, metadata, prev_hash, entry_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, ?)"
        )
        .bind(org_id).bind(event_type).bind(severity)
        .bind(entity_id).bind(session_id).bind(description)
        .bind(metadata).bind(&entry_hash).bind(now())
        .execute(self.inner()).await?;
        Ok(())
    }

    pub async fn get_recent_audit(
        &self,
        org_id: &str,
        limit: i64,
    ) -> Result<Vec<AuditEntry>, sqlx::Error> {
        sqlx::query_as(
            "SELECT * FROM audit_chain WHERE org_id = ? ORDER BY created_at DESC LIMIT ?",
        )
        .bind(org_id)
        .bind(limit)
        .fetch_all(self.inner())
        .await
    }

    // ═══ Security Incidents ═══

    pub async fn get_incidents(
        &self,
        org_id: &str,
    ) -> Result<Vec<SecurityIncidentRow>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM security_incidents WHERE org_id = ? OR org_id = 'system' ORDER BY detected_at DESC")
            .bind(org_id).fetch_all(self.inner()).await
    }

    pub async fn get_incident(&self, id: &str) -> Result<SecurityIncidentRow, sqlx::Error> {
        sqlx::query_as("SELECT * FROM security_incidents WHERE id = ?")
            .bind(id)
            .fetch_one(self.inner())
            .await
    }

    pub async fn resolve_incident(&self, id: &str) -> Result<u64, sqlx::Error> {
        let r = sqlx::query(
            "UPDATE security_incidents SET status = 'resolved', resolved_at = ? WHERE id = ?",
        )
        .bind(now())
        .bind(id)
        .execute(self.inner())
        .await?;
        Ok(r.rows_affected())
    }

    // ═══ Policies ═══

    pub async fn get_policies(&self, org_id: &str) -> Result<Vec<CommPolicy>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM comm_policies WHERE org_id = ? ORDER BY priority ASC")
            .bind(org_id)
            .fetch_all(self.inner())
            .await
    }

    pub async fn create_policy(&self, p: CommPolicy) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO comm_policies (id, org_id, name, source_type, dest_type, allowed_intents, max_sessions_per_hour, require_clearance_match, enabled, priority, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&p.id).bind(&p.org_id).bind(&p.name)
        .bind(&p.source_type).bind(&p.dest_type)
        .bind(&p.allowed_intents).bind(p.max_sessions_per_hour)
        .bind(p.require_clearance_match).bind(p.enabled)
        .bind(p.priority).bind(p.created_at)
        .execute(self.inner()).await?;
        Ok(())
    }

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
        // Dynamic update — only set provided fields
        let mut sets = Vec::new();
        let mut vals: Vec<String> = Vec::new();

        if let Some(v) = name {
            sets.push("name = ?");
            vals.push(v.to_string());
        }
        if let Some(v) = source_type {
            sets.push("source_type = ?");
            vals.push(v.to_string());
        }
        if let Some(v) = dest_type {
            sets.push("dest_type = ?");
            vals.push(v.to_string());
        }
        if let Some(v) = allowed_intents {
            sets.push("allowed_intents = ?");
            vals.push(v.to_string());
        }
        if let Some(v) = max_sph {
            sets.push("max_sessions_per_hour = ?");
            vals.push(v.to_string());
        }
        if let Some(v) = clearance {
            sets.push("require_clearance_match = ?");
            vals.push(v.to_string());
        }
        if let Some(v) = enabled {
            sets.push("enabled = ?");
            vals.push(v.to_string());
        }
        if let Some(v) = priority {
            sets.push("priority = ?");
            vals.push(v.to_string());
        }

        if sets.is_empty() {
            return Ok(0);
        }

        let sql = format!(
            "UPDATE comm_policies SET {} WHERE id = ? AND org_id = ?",
            sets.join(", ")
        );
        let mut q = sqlx::query(&sql);
        for v in &vals {
            q = q.bind(v);
        }
        q = q.bind(id).bind(org_id);
        let r = q.execute(self.inner()).await?;
        Ok(r.rows_affected())
    }

    pub async fn delete_policy(&self, id: &str, org_id: &str) -> Result<u64, sqlx::Error> {
        let r = sqlx::query("DELETE FROM comm_policies WHERE id = ? AND org_id = ?")
            .bind(id)
            .bind(org_id)
            .execute(self.inner())
            .await?;
        Ok(r.rows_affected())
    }

    // ═══ Stats ═══

    pub async fn get_stats(&self, uptime_secs: u64) -> Result<StatsResp, sqlx::Error> {
        let (active_sessions,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM sessions WHERE status = 'active'")
                .fetch_one(self.inner())
                .await
                .unwrap_or((0,));

        let (avg_trust,): (Option<f64>,) = sqlx::query_as("SELECT avg(trust_score) FROM sessions")
            .fetch_one(self.inner())
            .await
            .unwrap_or((None,));

        let today = now() - 86400;
        let (blocked_today,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM sessions WHERE verdict = 'Deny' AND started_at >= ?",
        )
        .bind(today)
        .fetch_one(self.inner())
        .await
        .unwrap_or((0,));

        let (ai_calls,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM sessions WHERE ai_latency_ms IS NOT NULL AND started_at >= ?",
        )
        .bind(today)
        .fetch_one(self.inner())
        .await
        .unwrap_or((0,));

        let (entities_online,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM entities WHERE last_seen > ? AND quarantined = 0")
                .bind(now() - 300)
                .fetch_one(self.inner())
                .await
                .unwrap_or((0,));

        let (threats_today,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM security_incidents WHERE detected_at >= ?")
                .bind(today)
                .fetch_one(self.inner())
                .await
                .unwrap_or((0,));

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
