-- Add PQ cryptography fields to entities table
-- All nullable — existing entities keep working without PQ key

ALTER TABLE entities ADD COLUMN crypto_algorithm TEXT NOT NULL DEFAULT 'Classical';
ALTER TABLE entities ADD COLUMN pq_public_key    TEXT;   -- hex-encoded ML-DSA-65 pubkey
ALTER TABLE entities ADD COLUMN pq_enrolled_at   INTEGER; -- when PQ was added

-- Track PQ migration status
CREATE TABLE IF NOT EXISTS pq_migration_log (
    entity_id        TEXT NOT NULL,
    migrated_at      INTEGER NOT NULL,
    old_algorithm    TEXT NOT NULL,
    new_algorithm    TEXT NOT NULL,
    new_entity_id    TEXT,  -- EntityID changes after PQ migration
    PRIMARY KEY (entity_id, migrated_at)
);
