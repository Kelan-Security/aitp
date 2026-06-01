use tokio::sync::{Semaphore, SemaphorePermit};

/// MemoryBudget manages concurrency limits for resource-intensive operations.
pub struct MemoryBudget {
    /// Max concurrent in-flight AI evaluations
    pub ai_semaphore: Semaphore,
    /// Max pending WebSocket events across all subscribers  
    pub ws_semaphore: Semaphore,
}

impl Default for MemoryBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBudget {
    pub fn new() -> Self {
        Self {
            // Max 50 concurrent AI evals (each ~2MB context)
            ai_semaphore: Semaphore::new(50),
            // Max 1000 queued WS events total
            ws_semaphore: Semaphore::new(1000),
        }
    }

    pub async fn acquire_ai_slot(&self) -> SemaphorePermit<'_> {
        self.ai_semaphore.acquire().await.unwrap()
    }
}
