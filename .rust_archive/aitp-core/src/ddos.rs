use crate::framing::AitpPacket;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct DDoSConfig {
    pub max_syn_per_ip_per_min: u32,
    pub global_syn_budget: u32,
}

impl Default for DDoSConfig {
    fn default() -> Self {
        Self {
            max_syn_per_ip_per_min: 100,
            global_syn_budget: 10_000,
        }
    }
}

pub struct RateBucket {
    pub count: u32,
    pub last_reset: Instant,
}

pub struct PowChallenge {
    pub nonce: [u8; 8],
    pub difficulty: u32,
    pub expires_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DDoSVerdict {
    Allow,
    RateLimit,
    SynFloodProtection,
    RequirePoW([u8; 8]),
    Blacklisted,
}

pub struct DDoSGuard {
    ip_rates: Arc<DashMap<IpAddr, RateBucket>>,
    syn_budget: Arc<AtomicU32>,
    pow_challenges: Arc<DashMap<IpAddr, PowChallenge>>,
    config: DDoSConfig,
    blacklist: Arc<DashMap<IpAddr, ()>>,
}

impl DDoSGuard {
    pub fn new(config: DDoSConfig) -> Self {
        Self {
            ip_rates: Arc::new(DashMap::new()),
            syn_budget: Arc::new(AtomicU32::new(config.global_syn_budget)),
            pow_challenges: Arc::new(DashMap::new()),
            config,
            blacklist: Arc::new(DashMap::new()),
        }
    }

    pub fn check_incoming(&self, src_ip: IpAddr, packet: &AitpPacket) -> DDoSVerdict {
        if self.is_blacklisted(src_ip) {
            return DDoSVerdict::Blacklisted;
        }

        if self.ip_rate_exceeded(src_ip) {
            return DDoSVerdict::RateLimit;
        }

        if packet.header.is_syn() {
            let budget = self.syn_budget.load(Ordering::Relaxed);
            if budget == 0 {
                return DDoSVerdict::SynFloodProtection;
            }

            if !self.has_valid_pow(src_ip, packet) {
                return DDoSVerdict::RequirePoW(self.issue_challenge(src_ip));
            }

            self.syn_budget.fetch_sub(1, Ordering::Relaxed);
        }

        DDoSVerdict::Allow
    }

    fn ip_rate_exceeded(&self, src_ip: IpAddr) -> bool {
        let mut bucket = self.ip_rates.entry(src_ip).or_insert_with(|| RateBucket {
            count: 0,
            last_reset: Instant::now(),
        });

        if bucket.last_reset.elapsed() > Duration::from_secs(60) {
            bucket.count = 0;
            bucket.last_reset = Instant::now();
        }

        bucket.count += 1;
        bucket.count > self.config.max_syn_per_ip_per_min
    }

    fn has_valid_pow(&self, _src_ip: IpAddr, _packet: &AitpPacket) -> bool {
        // Simplified for prototype: always true for known IPs or basic packets
        // In reality: verify hashcash-style PoW in payload or header extension
        true
    }

    fn issue_challenge(&self, _src_ip: IpAddr) -> [u8; 8] {
        [0; 8] // Placeholder for actual challenge generation
    }

    fn is_blacklisted(&self, src_ip: IpAddr) -> bool {
        self.blacklist.contains_key(&src_ip)
    }

    pub fn blacklist_ip(&self, ip: IpAddr) {
        self.blacklist.insert(ip, ());
    }

    pub fn replenish_budget(&self) {
        self.syn_budget
            .store(self.config.global_syn_budget, Ordering::Relaxed);
    }
}
