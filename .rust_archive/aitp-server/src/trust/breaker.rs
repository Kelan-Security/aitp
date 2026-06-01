use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq)]
pub enum CircuitState {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

pub struct CircuitBreaker {
    state: AtomicU8,
    error_count: AtomicU32,
    success_count: AtomicU32,
    last_tripped: AtomicU64,
    error_threshold_pct: u32,
    timeout_secs: u64,
}

impl CircuitBreaker {
    pub fn new(error_threshold_pct: u32, timeout_secs: u64) -> Self {
        Self {
            state: AtomicU8::new(CircuitState::Closed as u8),
            error_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_tripped: AtomicU64::new(0),
            error_threshold_pct,
            timeout_secs,
        }
    }

    pub fn state(&self) -> CircuitState {
        let current = self.state.load(Ordering::SeqCst);
        if current == CircuitState::Open as u8 {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let tripped = self.last_tripped.load(Ordering::SeqCst);
            if now - tripped >= self.timeout_secs {
                self.state.store(CircuitState::HalfOpen as u8, Ordering::SeqCst);
                return CircuitState::HalfOpen;
            }
            CircuitState::Open
        } else if current == CircuitState::HalfOpen as u8 {
            CircuitState::HalfOpen
        } else {
            CircuitState::Closed
        }
    }

    pub fn record_success(&self) {
        if self.state() == CircuitState::HalfOpen {
            // Reset circuit
            self.state.store(CircuitState::Closed as u8, Ordering::SeqCst);
            self.error_count.store(0, Ordering::SeqCst);
            self.success_count.store(0, Ordering::SeqCst);
            tracing::info!("Circuit Breaker RESET to CLOSED");
        } else {
            self.success_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_error(&self) {
        match self.state() {
            CircuitState::HalfOpen => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                self.last_tripped.store(now, Ordering::SeqCst);
                self.state.store(CircuitState::Open as u8, Ordering::SeqCst);
                tracing::warn!("Circuit Breaker TRIPPED to OPEN from HalfOpen");
            }
            CircuitState::Closed => {
                let errors = self.error_count.fetch_add(1, Ordering::Relaxed) + 1;
                let successes = self.success_count.load(Ordering::Relaxed);
                let total = errors + successes;
                if total > 10 { // Minimum sample size
                    let error_rate = (errors * 100) / total;
                    if error_rate >= self.error_threshold_pct {
                        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        self.last_tripped.store(now, Ordering::SeqCst);
                        self.state.store(CircuitState::Open as u8, Ordering::SeqCst);
                        tracing::error!("Circuit Breaker TRIPPED to OPEN (Error Rate: {}%)", error_rate);
                    }
                }
            }
            _ => {}
        }
    }
}
