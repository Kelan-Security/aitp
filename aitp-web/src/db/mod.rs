pub mod migrations;
pub mod models;
pub mod queries;

#[derive(Clone)]
pub struct DbPool {
    pool: sqlx::SqlitePool,
}

impl DbPool {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }

    pub fn inner(&self) -> &sqlx::SqlitePool {
        &self.pool
    }
}
