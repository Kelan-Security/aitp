// protocol/congestion.rs

use std::cmp::max;

/// Maintains AIMD congestion control state for a reliable session.
pub struct CongestionControl {
    /// Congestion window (number of in-flight packets allowed)
    pub cwnd: f64,
    /// Slow start threshold
    pub ssthresh: f64,
    /// Minimum allowed cwnd
    pub min_cwnd: f64,
    /// Maximum allowed cwnd
    pub max_cwnd: f64,
}

impl Default for CongestionControl {
    fn default() -> Self {
        Self {
            cwnd: 1.0,
            ssthresh: 64.0,
            min_cwnd: 1.0,
            max_cwnd: 128.0,
        }
    }
}

impl CongestionControl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Retrieve the current integer bound of the congestion window.
    pub fn cwnd_usize(&self) -> usize {
        self.cwnd as usize
    }

    /// Process a received positive acknowledgment.
    pub fn on_ack(&mut self) {
        if self.cwnd < self.ssthresh {
            // Slow start: exponential growth (adds 1 per ACK)
            self.cwnd += 1.0;
        } else {
            // Congestion avoidance: additive increase
            self.cwnd += 1.0 / self.cwnd;
        }

        if self.cwnd > self.max_cwnd {
            self.cwnd = self.max_cwnd;
        }
    }

    /// Process a packet loss explicitly triggered by a retransmission timeout.
    pub fn on_loss(&mut self) {
        self.ssthresh = max((self.cwnd / 2.0) as u32, 2) as f64;
        self.cwnd = self.min_cwnd;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aimd_slow_start_and_avoidance() {
        let mut cc = CongestionControl::new();
        cc.ssthresh = 4.0;
        
        // Slow start
        cc.on_ack();
        assert_eq!(cc.cwnd_usize(), 2);
        cc.on_ack();
        assert_eq!(cc.cwnd_usize(), 3);
        cc.on_ack();
        assert_eq!(cc.cwnd_usize(), 4);

        // Avoidance
        cc.on_ack();
        assert!(cc.cwnd > 4.0 && cc.cwnd < 5.0);
    }

    #[test]
    fn test_aimd_loss() {
        let mut cc = CongestionControl::new();
        cc.cwnd = 10.0;
        cc.on_loss();
        assert_eq!(cc.ssthresh, 5.0);
        assert_eq!(cc.cwnd_usize(), 1);
    }
}
