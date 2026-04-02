// trust/circuit_breaker.rs

use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;
use std::time::{Instant, Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,   // Normal operation
    Open,     // Reject all traffic -> use fallback
    HalfOpen, // Testing if service recovered
}

pub struct CircuitBreaker {
    state: RwLock<BreakerState>,
    last_state_change: RwLock<Instant>,

    // Sliding Window (60s) state
    success_count: AtomicUsize,
    failure_count: AtomicUsize,
    timeout_count: AtomicUsize,

    consecutive_timeouts: AtomicUsize,

    // Temporal bounded configurations
    window_secs: u64,
    failure_rate_threshold: f64,
    max_consecutive_timeouts: usize,
    half_open_timeout: Duration,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self {
            state: RwLock::new(BreakerState::Closed),
            last_state_change: RwLock::new(Instant::now()),
            success_count: AtomicUsize::new(0),
            failure_count: AtomicUsize::new(0),
            timeout_count: AtomicUsize::new(0),
            consecutive_timeouts: AtomicUsize::new(0),
            window_secs: 60,
            failure_rate_threshold: 0.30, // 30%
            max_consecutive_timeouts: 3,
            half_open_timeout: Duration::from_secs(30),
        }
    }
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluates if active routing should permit hitting external API
    pub async fn allow_request(&self) -> bool {
        let state = *self.state.read().await;

        match state {
            BreakerState::Closed => true,
            BreakerState::Open => {
                let last = *self.last_state_change.read().await;
                if last.elapsed() >= self.half_open_timeout {
                    let mut write_state = self.state.write().await;
                    // Double check nobody changed it while waiting for lock
                    if *write_state == BreakerState::Open {
                        *write_state = BreakerState::HalfOpen;
                        *self.last_state_change.write().await = Instant::now();
                        crate::metrics::GEMINI_CIRCUIT_BREAKER_STATE.set(2.0); // HalfOpen
                        return true; // Allow ONE probe request
                    }
                }
                false
            }
            BreakerState::HalfOpen => false, // Only one request allowed, subsequent requests fail fast until state resolves
        }
    }

    pub async fn record_success(&self) {
        self.success_count.fetch_add(1, Ordering::SeqCst);
        self.consecutive_timeouts.store(0, Ordering::SeqCst);

        let mut current_state = self.state.write().await;
        if *current_state == BreakerState::HalfOpen {
            *current_state = BreakerState::Closed;
            *self.last_state_change.write().await = Instant::now();
            self.reset_counters();
            crate::metrics::GEMINI_CIRCUIT_BREAKER_STATE.set(0.0); // Closed
        }
    }

    pub async fn record_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::SeqCst);
        self.consecutive_timeouts.store(0, Ordering::SeqCst);
        self.evaluate_trip().await;
    }

    pub async fn record_timeout(&self) {
        self.timeout_count.fetch_add(1, Ordering::SeqCst);
        self.consecutive_timeouts.fetch_add(1, Ordering::SeqCst);
        self.evaluate_trip().await;
    }

    async fn evaluate_trip(&self) {
        let state = *self.state.read().await;
        if state == BreakerState::Open {
            return;
        }

        if state == BreakerState::HalfOpen {
            // HalfOpen failed. Trip back to Open immediately.
            let mut write_state = self.state.write().await;
            *write_state = BreakerState::Open;
            *self.last_state_change.write().await = Instant::now();
            crate::metrics::GEMINI_CIRCUIT_BREAKER_STATE.set(1.0); // Open
            return;
        }

        let consec_timeouts = self.consecutive_timeouts.load(Ordering::SeqCst);
        if consec_timeouts > self.max_consecutive_timeouts {
            self.trip_breaker().await;
            return;
        }

        let fails = self.failure_count.load(Ordering::SeqCst) + self.timeout_count.load(Ordering::SeqCst);
        let successes = self.success_count.load(Ordering::SeqCst);
        let total = fails + successes;

        if total > 5 { // Require minimum sample size
            let fail_rate = fails as f64 / total as f64;
            if fail_rate > self.failure_rate_threshold {
                self.trip_breaker().await;
            }
        }
    }

    async fn trip_breaker(&self) {
        let mut write_state = self.state.write().await;
        if *write_state != BreakerState::Open {
            *write_state = BreakerState::Open;
            *self.last_state_change.write().await = Instant::now();
            crate::metrics::GEMINI_CIRCUIT_BREAKER_STATE.set(1.0); // Open
            tracing::error!("Gemini Circuit Breaker TRIPPED OPEN. Fallback Rules engaged.");
        }
    }

    /// Background interval should call this every 60s
    pub fn reset_counters(&self) {
        self.success_count.store(0, Ordering::SeqCst);
        self.failure_count.store(0, Ordering::SeqCst);
        self.timeout_count.store(0, Ordering::SeqCst);
        self.consecutive_timeouts.store(0, Ordering::SeqCst);
    }
}
