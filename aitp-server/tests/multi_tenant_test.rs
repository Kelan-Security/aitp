use assert_cmd::Command;
use sqlx::{Pool, Sqlite};

#[tokio::test]
async fn test_multitenant_baseline_isolation() -> anyhow::Result<()> {
    // 1. Setup in-memory SQLite DB
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await?;
    
    // 2. Setup schema using migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    // 3. Create two orgs
    sqlx::query("INSERT INTO organisations (id, name, email, password_hash, trust_mode, created_at) VALUES ('org1', 'First Org', 'sys1', 'hash', 'hybrid', 0)")
        .execute(&pool).await?;
    sqlx::query("INSERT INTO organisations (id, name, email, password_hash, trust_mode, created_at) VALUES ('org2', 'Second Org', 'sys2', 'hash', 'hybrid', 0)")
        .execute(&pool).await?;

    // 4. Create an entity with the same ID but under two orgs (or simulate baselines with same entity ID to check isolation)
    sqlx::query("INSERT INTO entity_baselines (org_id, entity_id, last_updated) VALUES ('org1', 'SHARED_ENTITY', 0)")
        .execute(&pool).await?;
    sqlx::query("INSERT INTO entity_baselines (org_id, entity_id, last_updated) VALUES ('org2', 'SHARED_ENTITY', 0)")
        .execute(&pool).await?;

    // 5. Verify they are stored as separate rows and scoped to org
    let count1: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entity_baselines WHERE org_id = 'org1' AND entity_id = 'SHARED_ENTITY'")
        .fetch_one(&pool).await?;
    let count2: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entity_baselines WHERE org_id = 'org2' AND entity_id = 'SHARED_ENTITY'")
        .fetch_one(&pool).await?;
    
    assert_eq!(count1, 1, "Org1 should have its own isolated baseline bucket");
    assert_eq!(count2, 1, "Org2 should have its own isolated baseline bucket");

    // 6. Delete org1 and verify cascade delete constraints
    sqlx::query("DELETE FROM organisations WHERE id = 'org1'")
        .execute(&pool).await?;

    let count1_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entity_baselines WHERE org_id = 'org1'")
        .fetch_one(&pool).await?;
    assert_eq!(count1_after, 0, "All org1 data must cascade delete upon tenant pruning");

    let count2_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entity_baselines WHERE org_id = 'org2'")
        .fetch_one(&pool).await?;
    assert_eq!(count2_after, 1, "Org2 data must remain perfectly intact after other tenant is pruned");

    Ok(())
}
