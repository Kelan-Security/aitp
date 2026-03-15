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
    /// Runs all pending migrations immediately after connecting.
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
            tracing::info!("Database: SQLite (development mode)");

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
                .min_connections(1)
                .acquire_timeout(std::time::Duration::from_secs(5))
                .idle_timeout(std::time::Duration::from_secs(300))
                .connect(url)
                .await?;

            // SQLite pragmas — must run before migrations
            sqlx::query("PRAGMA journal_mode=WAL").execute(&pool).await?;
            sqlx::query("PRAGMA synchronous=NORMAL").execute(&pool).await?;
            sqlx::query("PRAGMA foreign_keys=ON").execute(&pool).await?;
            sqlx::query("PRAGMA busy_timeout=5000").execute(&pool).await?;

            let db = DbPool::Sqlite(pool);
            db.run_migrations().await?;
            Ok(db)

        } else if url.starts_with("postgres") || url.starts_with("postgresql") {
            tracing::info!("Database: PostgreSQL (production mode)");

            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(pool_size as u32)
                .min_connections(2)
                .acquire_timeout(std::time::Duration::from_secs(10))
                .idle_timeout(std::time::Duration::from_secs(300))
                .connect(url)
                .await?;

            let db = DbPool::Postgres(pool);
            db.run_migrations().await?;
            Ok(db)

        } else {
            anyhow::bail!(
                "Unsupported DATABASE_URL: '{}'\n\
                 Must start with 'sqlite://' or 'postgres://'",
                &url[..url.len().min(40)]
            )
        }
    }

    /// Run all migrations in migrations/ directory.
    async fn run_migrations(&self) -> anyhow::Result<()> {
        match self {
            DbPool::Sqlite(pool) => {
                sqlx::migrate!("./migrations")
                    .run(pool)
                    .await
                    .map_err(|e| anyhow::anyhow!("SQLite migration failed: {}", e))?;
            }
            DbPool::Postgres(pool) => {
                sqlx::migrate!("./migrations")
                    .run(pool)
                    .await
                    .map_err(|e| anyhow::anyhow!("PostgreSQL migration failed: {}", e))?;
            }
        }
        tracing::info!("Migrations complete — 7 tables");
        Ok(())
    }

    #[allow(dead_code)]
    pub fn is_postgres(&self) -> bool {
        matches!(self, DbPool::Postgres(_))
    }

    #[allow(dead_code)]
    pub fn is_sqlite(&self) -> bool {
        matches!(self, DbPool::Sqlite(_))
    }
}
