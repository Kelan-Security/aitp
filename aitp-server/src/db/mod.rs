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
                .max_connections(10)
                .connect(url)
                .await?;
            Ok(Self::Sqlite(pool))
        } else if url.starts_with("postgres") || url.starts_with("postgresql") {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(50)
                .connect(url)
                .await?;
            Ok(Self::Postgres(pool))
        } else {
            anyhow::bail!("Unsupported DATABASE_URL: must start with sqlite:// or postgres://")
        }
    }
}
