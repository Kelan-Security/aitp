use crate::db::{models::*, DbPool};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

impl DbPool {
    pub async fn create_org(&self, org: Organization) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO organizations (id, name, email, password_hash, industry, gemini_api_key_enc, claude_api_key_enc, openai_api_key_enc, ai_provider, ai_model, trust_mode, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(org.id)
        .bind(org.name)
        .bind(org.email)
        .bind(org.password_hash)
        .bind(org.industry)
        .bind(org.gemini_api_key_enc)
        .bind(org.claude_api_key_enc)
        .bind(org.openai_api_key_enc)
        .bind(org.ai_provider)
        .bind(org.ai_model)
        .bind(org.trust_mode)
        .bind(org.created_at)
        .execute(self.inner())
        .await?;
        Ok(())
    }

    pub async fn get_org_by_email(&self, email: &str) -> Result<Organization, sqlx::Error> {
        sqlx::query_as("SELECT * FROM organizations WHERE email = ?")
            .bind(email)
            .fetch_one(self.inner())
            .await
    }

    pub async fn get_org_by_id(&self, id: &str) -> Result<Organization, sqlx::Error> {
        sqlx::query_as("SELECT * FROM organizations WHERE id = ?")
            .bind(id)
            .fetch_one(self.inner())
            .await
    }

    pub async fn update_org_login(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE organizations SET last_login = ? WHERE id = ?")
            .bind(now())
            .bind(id)
            .execute(self.inner())
            .await?;
        Ok(())
    }

    pub async fn update_ai_config(
        &self,
        id: &str,
        provider: &str,
        model: &str,
        trust_mode: &str,
        enc_key: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let mut q =
            "UPDATE organizations SET ai_provider = ?, ai_model = ?, trust_mode = ?".to_string();
        if provider == "gemini" && enc_key.is_some() {
            q += ", gemini_api_key_enc = ?";
        } else if provider == "claude" && enc_key.is_some() {
            q += ", claude_api_key_enc = ?";
        } else if provider == "openai" && enc_key.is_some() {
            q += ", openai_api_key_enc = ?";
        }
        q += " WHERE id = ?";

        let mut query = sqlx::query(&q).bind(provider).bind(model).bind(trust_mode);

        if let Some(key) = enc_key {
            query = query.bind(key);
        }

        query.bind(id).execute(self.inner()).await?;
        Ok(())
    }

    pub async fn get_servers(&self, org_id: &str) -> Result<Vec<ServerNode>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM server_nodes WHERE org_id = ? ORDER BY created_at DESC")
            .bind(org_id)
            .fetch_all(self.inner())
            .await
    }

    pub async fn create_server(&self, node: ServerNode) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO server_nodes (id, org_id, name, listen_address, listen_port, entity_id, public_key, private_key_path, status, client_count, session_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(node.id)
            .bind(node.org_id)
            .bind(node.name)
            .bind(node.listen_address)
            .bind(node.listen_port)
            .bind(node.entity_id)
            .bind(node.public_key)
            .bind(node.private_key_path)
            .bind(node.status)
            .bind(node.client_count)
            .bind(node.session_count)
            .bind(node.created_at)
            .execute(self.inner())
            .await?;
        Ok(())
    }

    pub async fn delete_server(&self, org_id: &str, id: &str) -> Result<u64, sqlx::Error> {
        let res = sqlx::query("DELETE FROM server_nodes WHERE org_id = ? AND id = ?")
            .bind(org_id)
            .bind(id)
            .execute(self.inner())
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn get_clients(&self, org_id: &str) -> Result<Vec<ClientNode>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM client_nodes WHERE org_id = ? ORDER BY created_at DESC")
            .bind(org_id)
            .fetch_all(self.inner())
            .await
    }

    pub async fn create_client(&self, node: ClientNode) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO client_nodes (id, org_id, name, entity_id, public_key, private_key_path, allowed_intents, trust_score, session_count, blocked_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(node.id)
            .bind(node.org_id)
            .bind(node.name)
            .bind(node.entity_id)
            .bind(node.public_key)
            .bind(node.private_key_path)
            .bind(node.allowed_intents)
            .bind(node.trust_score)
            .bind(node.session_count)
            .bind(node.blocked_count)
            .bind(node.created_at)
            .execute(self.inner())
            .await?;
        Ok(())
    }

    pub async fn delete_client(&self, org_id: &str, id: &str) -> Result<u64, sqlx::Error> {
        let res = sqlx::query("DELETE FROM client_nodes WHERE org_id = ? AND id = ?")
            .bind(org_id)
            .bind(id)
            .execute(self.inner())
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn get_sessions(
        &self,
        org_id: &str,
        active_only: bool,
    ) -> Result<Vec<Session>, sqlx::Error> {
        let query = if active_only {
            "SELECT * FROM sessions WHERE org_id = ? AND status = 'active' ORDER BY started_at DESC"
        } else {
            "SELECT * FROM sessions WHERE org_id = ? ORDER BY started_at DESC LIMIT 100"
        };
        sqlx::query_as(query)
            .bind(org_id)
            .fetch_all(self.inner())
            .await
    }

    pub async fn close_session(
        &self,
        session_id: &str,
        reason: &str,
        tx: i64,
        rx: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sessions SET status = 'closed', ended_at = ?, close_reason = ?, bytes_tx = bytes_tx + ?, bytes_rx = bytes_rx + ? WHERE id = ? AND status = 'active'")
            .bind(now())
            .bind(reason)
            .bind(tx)
            .bind(rx)
            .bind(session_id)
            .execute(self.inner())
            .await?;
        Ok(())
    }

    pub async fn get_recent_events(
        &self,
        org_id: &str,
        limit: i64,
    ) -> Result<Vec<AuditEvent>, sqlx::Error> {
        sqlx::query_as(
            "SELECT * FROM audit_events WHERE org_id = ? ORDER BY created_at DESC LIMIT ?",
        )
        .bind(org_id)
        .bind(limit)
        .fetch_all(self.inner())
        .await
    }

    #[allow(dead_code)]
    pub async fn create_event(&self, event: AuditEvent) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO audit_events (id, org_id, event_type, severity, source_ip, entity_id, session_id, description, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(event.id)
            .bind(event.org_id)
            .bind(event.event_type)
            .bind(event.severity)
            .bind(event.source_ip)
            .bind(event.entity_id)
            .bind(event.session_id)
            .bind(event.description)
            .bind(event.metadata)
            .bind(event.created_at)
            .execute(self.inner())
            .await?;
        Ok(())
    }

    pub async fn get_stats(&self, uptime_secs: u64) -> Result<StatsResp, sqlx::Error> {
        let (active_sessions,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM sessions WHERE status = 'active'")
                .fetch_one(self.inner())
                .await
                .unwrap_or((0,));

        let (total_sessions,): (i64,) = sqlx::query_as("SELECT count(*) FROM sessions")
            .fetch_one(self.inner())
            .await
            .unwrap_or((0,));

        let (mut avg_trust,): (Option<f64>,) =
            sqlx::query_as("SELECT avg(trust_score) FROM sessions WHERE status = 'active'")
                .fetch_one(self.inner())
                .await
                .unwrap_or((None,));
        if avg_trust.is_none() {
            let (overall_avg,): (Option<f64>,) =
                sqlx::query_as("SELECT avg(trust_score) FROM sessions")
                    .fetch_one(self.inner())
                    .await
                    .unwrap_or((None,));
            avg_trust = overall_avg;
        }

        let today = now() - 86400;
        let (blocked_today,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM audit_events WHERE severity = 'ERROR' AND created_at >= ?",
        )
        .bind(today)
        .fetch_one(self.inner())
        .await
        .unwrap_or((0,));

        let (ai_calls_today,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM audit_events WHERE event_type LIKE '%eval%' AND created_at >= ?",
        )
        .bind(today)
        .fetch_one(self.inner())
        .await
        .unwrap_or((0,));

        let (avg_ai_latency_ms,): (Option<f64>,) = sqlx::query_as(
            "SELECT avg(ai_latency_ms) FROM sessions WHERE ai_latency_ms IS NOT NULL",
        )
        .fetch_one(self.inner())
        .await
        .unwrap_or((None,));

        let (server_nodes_online,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM server_nodes WHERE status = 'online'")
                .fetch_one(self.inner())
                .await
                .unwrap_or((0,));

        let (client_nodes_total,): (i64,) = sqlx::query_as("SELECT count(*) FROM client_nodes")
            .fetch_one(self.inner())
            .await
            .unwrap_or((0,));

        Ok(StatsResp {
            active_sessions,
            total_sessions,
            avg_trust_score: avg_trust,
            blocked_today,
            ai_calls_today,
            avg_ai_latency_ms,
            server_nodes_online,
            client_nodes_total,
            uptime_seconds: uptime_secs,
        })
    }
}
