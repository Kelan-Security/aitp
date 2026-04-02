// persistence/write_buffer.rs

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

/// Generic anomaly event struct referencing the expected fields in the prompt.
#[derive(Debug, Clone)]
pub struct AnomalyEvent {
    pub session_id: String,
    pub org_id: String,
    pub signal_type: String,
    pub score: f64,
    pub detected_at: i64,
    pub severity: String,
}

pub struct DbWriteBuffer<T> {
    pub buffer: Arc<Mutex<Vec<T>>>,
    pub max_size: usize,
    pub overflow_limit: usize,
}

impl<T: Send + Sync + 'static + Clone> DbWriteBuffer<T> {
    pub fn new(max_size: usize, overflow_limit: usize) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::with_capacity(max_size))),
            max_size,
            overflow_limit,
        }
    }

    /// Appends element synchronously enforcing memory backpressure bounds.
    pub async fn push(&self, item: T) -> Result<(), &'static str> {
        let mut buf = self.buffer.lock().await;

        if buf.len() > self.overflow_limit {
            crate::metrics::DB_WRITE_BUFFER_OVERFLOW.inc();
            tracing::error!("CRITICAL: DB Write buffer exceeded absolute maximum of {}", self.overflow_limit);
            // Typically here we would check `item` traits and drop if Level == INFO,
            // but for generic encapsulation we reject gracefully pushing backpressure upwards.
            return Err("Buffer capacity exhausted");
        }

        buf.push(item);
        Ok(())
    }

    pub async fn drain_all(&self) -> Vec<T> {
        let mut buf = self.buffer.lock().await;
        if buf.is_empty() {
            return Vec::new();
        }
        let drained: Vec<T> = buf.drain(..).collect();
        crate::metrics::DB_WRITE_BATCH_SIZE.observe(drained.len() as f64);
        drained
    }

    /// Spawns the background autonomous sweeping logic triggering the generic callback on bounds hit
    pub async fn spawn_flusher<F, Fut>(self: Arc<Self>, mut callback: F)
    where
        F: FnMut(Vec<T>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(100));
            loop {
                ticker.tick().await;

                // Time triggered check
                let count = self.buffer.lock().await.len();
                crate::metrics::DB_WRITE_BUFFER_SIZE.set(count as f64);
                
                if count > 0 {
                    // Extract block regardless if size >= max_size or simply 100ms elapsed
                    let items = self.drain_all().await;
                    if !items.is_empty() {
                        let start = std::time::Instant::now();
                        callback(items).await;
                        crate::metrics::DB_WRITE_FLUSH_DURATION.observe(start.elapsed().as_secs_f64());
                    }
                }
            }
        });
    }
}
