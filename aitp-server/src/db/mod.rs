use sqlx::{Pool, Postgres, Sqlite};

pub mod migrations;
pub mod models;
pub mod queries;

/// Enum wrapping the underlying database connection pool.
/// Allows transparent switching between SQLite (local/dev) and PostgreSQL (production).
#[derive(Clone, Debug)]
pub enum DbPool {
    Sqlite(Pool<Sqlite>),
    Postgres(Pool<Postgres>),
}

impl DbPool {
    /// Connects to the database by inspecting the URL prefix.
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let cpus = num_cpus::get();
        
        let pool_size = std::env::var("DB_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                if url.starts_with("sqlite") {
                    (cpus * 2).min(10)
                } else {
                    (cpus * 4).min(40)
                }
            });

        if url.starts_with("sqlite") {
            // Ensure local file and parent path exists
            let path_str = url.trim_start_matches("sqlite://").trim_start_matches("sqlite:");
            let path = std::path::Path::new(path_str);
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            if !path.exists() {
                std::fs::File::create(path)?;
            }

            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(pool_size as u32)
                .min_connections(2)
                .acquire_timeout(std::time::Duration::from_secs(5))
                .idle_timeout(std::time::Duration::from_secs(300))
                .connect(url)
                .await?;
            Ok(Self::Sqlite(pool))
        } else if url.starts_with("postgres") || url.starts_with("postgresql") {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(pool_size as u32)
                .min_connections(2)
                .acquire_timeout(std::time::Duration::from_secs(5))
                .idle_timeout(std::time::Duration::from_secs(300))
                .connect(url)
                .await?;
            Ok(Self::Postgres(pool))
        } else {
            anyhow::bail!("Unsupported DATABASE_URL: must start with sqlite:// or postgres://")
        }
    }
}
