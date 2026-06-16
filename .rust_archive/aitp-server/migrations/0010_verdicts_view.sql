-- Migration: create verdicts view as an alias for sessions table.
-- Compatible with both SQLite and PostgreSQL.
CREATE VIEW IF NOT EXISTS verdicts AS SELECT * FROM sessions;
