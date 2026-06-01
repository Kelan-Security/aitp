// persistence/bulk_insert.rs

use crate::db::DbPool;
use crate::persistence::write_buffer::AnomalyEvent;

/// Abstract interface enforcing batch SQL flushes correctly scaling with pool connections.
pub async fn execute_bulk_insert(pool: &DbPool, batch: Vec<AnomalyEvent>) -> Result<(), sqlx::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    match pool {
        DbPool::Postgres(pg) => {
            // UNNEST optimized pathway mapping directly natively resolving SQL contention limits
            let mut session_ids = Vec::with_capacity(batch.len());
            let mut org_ids = Vec::with_capacity(batch.len());
            let mut signal_types = Vec::with_capacity(batch.len());
            let mut scores = Vec::with_capacity(batch.len());
            let mut detected_ats = Vec::with_capacity(batch.len());

            for evt in batch {
                session_ids.push(evt.session_id);
                org_ids.push(evt.org_id);
                signal_types.push(evt.signal_type);
                scores.push(evt.score);
                detected_ats.push(evt.detected_at);
            }

            let query = "
                INSERT INTO anomaly_events (session_id, org_id, signal_type, score, detected_at)
                SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::float8[], $5::bigint[])
            ";

            let mut sq = sqlx::query(query);
            sq = sq.bind(&session_ids).bind(&org_ids).bind(&signal_types).bind(&scores).bind(&detected_ats);
            sq.execute(pg).await?;
        }
        DbPool::Sqlite(sl) => {
            // Generates batch (?), (?), (?) dynamically mapping strings out directly circumventing query limitations
            let placeholders = batch.iter().map(|_| "(?, ?, ?, ?, ?)").collect::<Vec<_>>().join(", ");
            let query = format!(
                "INSERT INTO anomaly_events (session_id, org_id, signal_type, score, detected_at) VALUES {}",
                placeholders
            );

            let mut sq = sqlx::query(&query);
            for evt in batch {
                sq = sq
                    .bind(evt.session_id)
                    .bind(evt.org_id)
                    .bind(evt.signal_type)
                    .bind(evt.score)
                    .bind(evt.detected_at);
            }

            sq.execute(sl).await?;
        }
    }
    
    Ok(())
}
