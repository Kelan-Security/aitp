//! AI Intent Fingerprinting — behavioral divergence detection.
//!
//! Every session builds an "intent fingerprint": a rolling statistical profile
//! of what an entity **actually does** vs what it **declared** at handshake.
//!
//! If the two diverge (e.g., entity declared `ModelInference` but sends packets
//! at `ControlSignal` frequency patterns), the divergence score rises and the
//! server generates an `IntentMismatch` alert.
//!
//! # Divergence scoring
//!
//! - `0.0` — behavior perfectly matches declared intent
//! - `0.4` — threshold; anomaly flag set, server alert generated
//! - `1.0` — completely different from declared intent
//!
//! Scoring is based on three weighted sub-scores:
//! 1. **Packet rate** (30 %) — messages/second vs expected range for the intent
//! 2. **Payload size distribution** (40 %) — avg bytes vs expected range
//! 3. **Burst timing** (30 %) — inter-arrival variance vs expected range

use crate::header::IntentCode;
use std::collections::VecDeque;
use std::time::Instant;

// ────────────────────────── Expected Profiles ──────────────────────────

/// Expected behavioral profile for each intent code.
///
/// Tuples are `(rate_min, rate_max, size_min, size_max)` where rate is
/// packets/second and size is bytes/packet.
fn expected_profile(intent: IntentCode) -> (f32, f32, u32, u32) {
    match intent {
        // Inference: bursty, large payloads (model weights / embeddings)
        IntentCode::ModelInference => (0.5, 20.0, 512, 65000),
        // Data sync: moderate rate, medium-to-large payloads
        IntentCode::DataSync => (1.0, 50.0, 256, 8192),
        // Control signals: very low rate, tiny payloads
        IntentCode::ControlSignal => (0.1, 5.0, 16, 256),
        // Telemetry: steady moderate rate, small payloads
        IntentCode::Telemetry => (1.0, 30.0, 64, 512),
        // Agent coordination: low rate, variable sizes
        IntentCode::AgentCoordinate => (0.5, 10.0, 128, 4096),
        // File transfer: high rate, max-size datagrams
        IntentCode::FileTransfer => (10.0, 500.0, 8192, 65000),
        // Heartbeat: very low rate, near-zero payload
        IntentCode::Heartbeat => (0.01, 2.0, 0, 64),
        // Unknown: no expectations — always 0.0 divergence
        IntentCode::Unknown => (0.0, 1000.0, 0, 65000),
    }
}

// ────────────────────────── BehaviorVector ──────────────────────────

/// Rolling-window statistics over the last N packets.
#[derive(Debug, Clone)]
pub struct BehaviorVector {
    /// Inter-arrival timestamps (last 64 packets).
    arrivals: VecDeque<Instant>,
    /// Payload sizes (bytes) for the last 64 packets.
    sizes: VecDeque<u32>,
    /// Window size.
    window: usize,
}

impl BehaviorVector {
    /// Create a new behavior vector with the given rolling window size.
    pub fn new(window: usize) -> Self {
        Self {
            arrivals: VecDeque::with_capacity(window + 1),
            sizes: VecDeque::with_capacity(window + 1),
            window,
        }
    }

    /// Record a packet arriving with the given payload size.
    pub fn record(&mut self, payload_bytes: u32) {
        let now = Instant::now();
        self.arrivals.push_back(now);
        self.sizes.push_back(payload_bytes);
        if self.arrivals.len() > self.window {
            self.arrivals.pop_front();
            self.sizes.pop_front();
        }
    }

    /// Number of packets recorded so far.
    pub fn count(&self) -> usize {
        self.arrivals.len()
    }

    /// Average packet rate (packets/second) over the window.
    ///
    /// Returns `None` if fewer than 2 packets have been recorded.
    pub fn avg_rate_pps(&self) -> Option<f32> {
        if self.arrivals.len() < 2 {
            return None;
        }
        let first = *self.arrivals.front()?;
        let last = *self.arrivals.back()?;
        let elapsed = last.duration_since(first).as_secs_f32();
        if elapsed < 1e-6 {
            return None;
        }
        Some((self.arrivals.len() as f32 - 1.0) / elapsed)
    }

    /// Average payload size (bytes) over the window.
    pub fn avg_size_bytes(&self) -> f32 {
        if self.sizes.is_empty() {
            return 0.0;
        }
        self.sizes.iter().sum::<u32>() as f32 / self.sizes.len() as f32
    }

    /// Coefficient of variation (stddev/mean) of inter-arrival times.
    ///
    /// High CoV → bursty traffic; low CoV → steady.
    pub fn inter_arrival_cov(&self) -> f32 {
        if self.arrivals.len() < 3 {
            return 0.0;
        }
        let gaps: Vec<f32> = self
            .arrivals
            .iter()
            .zip(self.arrivals.iter().skip(1))
            .map(|(a, b)| b.duration_since(*a).as_secs_f32())
            .collect();

        let mean: f32 = gaps.iter().sum::<f32>() / gaps.len() as f32;
        if mean < 1e-9 {
            return 0.0;
        }
        let variance: f32 =
            gaps.iter().map(|g| (g - mean).powi(2)).sum::<f32>() / gaps.len() as f32;
        variance.sqrt() / mean
    }
}

impl Default for BehaviorVector {
    fn default() -> Self {
        Self::new(64)
    }
}

// ────────────────────────── IntentFingerprint ──────────────────────────

/// Behavioral fingerprint tracking divergence between declared and observed intent.
#[derive(Debug, Clone)]
pub struct IntentFingerprint {
    /// The intent code declared at session handshake.
    pub declared_intent: IntentCode,
    /// Rolling behavioral stats.
    pub observed: BehaviorVector,
    /// Most recently computed divergence score (0.0 = match, 1.0 = completely different).
    pub divergence_score: f32,
    /// Whether an anomaly has been flagged (score > 0.4).
    pub anomaly_detected: bool,
    /// How many consecutive samples exceeded the anomaly threshold.
    pub consecutive_anomalies: u32,
}

impl IntentFingerprint {
    /// Create a new fingerprint for the given declared intent.
    pub fn new(declared_intent: IntentCode) -> Self {
        Self {
            declared_intent,
            observed: BehaviorVector::default(),
            divergence_score: 0.0,
            anomaly_detected: false,
            consecutive_anomalies: 0,
        }
    }

    /// Record a new packet and recompute the divergence score.
    ///
    /// Returns `true` if an anomaly is newly detected (score crossed the 0.4 threshold).
    pub fn record_packet(&mut self, payload_bytes: u32) -> bool {
        self.observed.record(payload_bytes);

        // Need at least 10 samples to compute a meaningful score.
        if self.observed.count() < 10 {
            return false;
        }

        let was_anomaly = self.anomaly_detected;
        self.divergence_score = self.compute_divergence();
        self.anomaly_detected = self.divergence_score > 0.4;

        if self.anomaly_detected {
            self.consecutive_anomalies += 1;
        } else {
            self.consecutive_anomalies = 0;
        }

        // Return true only when anomaly is *newly* detected.
        !was_anomaly && self.anomaly_detected
    }

    /// Compute the 0.0–1.0 divergence score from the current behavior vector.
    fn compute_divergence(&self) -> f32 {
        let (rate_min, rate_max, size_min, size_max) = expected_profile(self.declared_intent);

        // Sub-score 1: packet rate (weight 30%)
        let rate_score = match self.observed.avg_rate_pps() {
            Some(r) => {
                if r < rate_min {
                    ((rate_min - r) / rate_min).min(1.0)
                } else if r > rate_max {
                    ((r - rate_max) / rate_max).min(1.0)
                } else {
                    0.0
                }
            }
            None => 0.0,
        };

        // Sub-score 2: average payload size (weight 40%)
        let avg_size = self.observed.avg_size_bytes();
        let size_score = if avg_size < size_min as f32 {
            if size_min == 0 {
                0.0
            } else {
                ((size_min as f32 - avg_size) / size_min as f32).min(1.0)
            }
        } else if avg_size > size_max as f32 {
            ((avg_size - size_max as f32) / size_max as f32).min(1.0)
        } else {
            0.0
        };

        // Sub-score 3: timing variance (weight 30%)
        // Control signals are expected to be steady (low CoV).
        // Inference is expected to be bursty (high CoV).
        let cov = self.observed.inter_arrival_cov();
        let timing_score = match self.declared_intent {
            IntentCode::ControlSignal | IntentCode::Telemetry | IntentCode::Heartbeat => {
                // Low variance expected; high CoV = anomaly.
                (cov - 0.5).max(0.0).min(1.0)
            }
            IntentCode::ModelInference | IntentCode::FileTransfer => {
                // High variance (bursts) is normal; very low CoV is suspicious.
                (0.2 - cov).max(0.0).min(1.0) * 0.5
            }
            _ => 0.0,
        };

        0.30 * rate_score + 0.40 * size_score + 0.30 * timing_score
    }

    /// Human-readable explanation of the current divergence.
    pub fn describe_divergence(&self) -> String {
        if self.divergence_score <= 0.1 {
            return "behavior matches declared intent".to_string();
        }
        let (rate_min, rate_max, size_min, size_max) = expected_profile(self.declared_intent);
        let actual_rate = self.observed.avg_rate_pps().unwrap_or(0.0);
        let actual_size = self.observed.avg_size_bytes();
        format!(
            "score={:.2} | rate={:.1}pps (expected {:.1}-{:.1}) | size={:.0}B (expected {}-{})",
            self.divergence_score, actual_rate, rate_min, rate_max, actual_size, size_min, size_max,
        )
    }
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_behavior_vector_rate() {
        let mut bv = BehaviorVector::new(64);
        // Record 10 packets with ~10ms spacing → ~100pps
        for _ in 0..10 {
            bv.record(512);
            thread::sleep(Duration::from_millis(10));
        }
        let rate = bv.avg_rate_pps().unwrap();
        assert!(rate > 50.0 && rate < 200.0, "rate={rate}");
    }

    #[test]
    fn test_no_anomaly_for_matching_intent() {
        let mut fp = IntentFingerprint::new(IntentCode::Telemetry);
        // Telemetry: expected 1-30 pps, 64-512 bytes
        for _ in 0..15 {
            let new_anomaly = fp.record_packet(256);
            thread::sleep(Duration::from_millis(50)); // ~20 pps — within range
            let _ = new_anomaly; // ignore early ones
        }
        // After 15 samples the score should be low.
        assert!(
            fp.divergence_score < 0.4,
            "Expected no anomaly for matching telemetry behavior, score={}",
            fp.divergence_score
        );
    }

    #[test]
    fn test_anomaly_for_tiny_inference_payloads() {
        let mut fp = IntentFingerprint::new(IntentCode::ModelInference);
        // ModelInference expects 512-65000 byte payloads. Sending 1-byte packets.
        for _ in 0..15 {
            fp.record_packet(1);
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            fp.divergence_score > 0.3,
            "Expected elevated divergence for suspiciously small inference packets, score={}",
            fp.divergence_score
        );
    }

    #[test]
    fn test_divergence_describe() {
        let mut fp = IntentFingerprint::new(IntentCode::ControlSignal);
        for _ in 0..10 {
            fp.record_packet(10000); // huge payload for control signal
            thread::sleep(Duration::from_millis(10));
        }
        let desc = fp.describe_divergence();
        assert!(!desc.is_empty());
    }
}
