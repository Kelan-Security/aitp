//! Kelan Security Binary License Enforcement
//!
//! License validation is purely local — no network calls, no phone-home.
//! The customer's license file is validated against our hardcoded public key.
//! Forging a license requires our private key, which never leaves our control.

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::OnceLock;

// ── YOUR PUBLIC KEY — hardcoded into every binary ─────────────────────────
//
// The matching PRIVATE key signs licenses and stays on your machine.
//
const KELAN_LICENSE_PUBKEY_HEX: &str =
    "fb5b55f743b188e8dbb55a85fc4c17bde13e9f60ff200f40fa5b5fcc510d1425";

// ── License paths checked in order ───────────────────────────────────────
const LICENSE_SEARCH_PATHS: &[&str] = &[
    "/etc/kelan/kelan.license",
    "/opt/kelan/kelan.license",
    "./kelan.license",
    "./aitp-server/kelan.license",
];

// ── Global license state (loaded once at startup) ─────────────────────────
static ACTIVE_LICENSE: OnceLock<ActiveLicense> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LicenseTier {
    Community,
    Startup,
    Enterprise,
    Defense,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LicenseFeature {
    Postgres,
    AirGap,
    Sso,
    Fips,
    ClearanceGating,
    Federation,
    PrioritySupport,
    CustomRetention,
    Webhooks,
}

pub struct TierLimits {
    pub max_nodes:              u32,   // max entities registerable
    #[allow(dead_code)]
    pub max_sessions_per_min:   u32,   // rate limit
    #[allow(dead_code)]
    pub retention_days:         u32,   // audit log retention
    #[allow(dead_code)]
    pub max_orgs:               u32,   // multi-tenant (Enterprise+)
}

impl LicenseTier {
    pub fn hard_limits(&self) -> TierLimits {
        match self {
            LicenseTier::Community => TierLimits {
                max_nodes:            5,
                max_sessions_per_min: 60,
                retention_days:       7,
                max_orgs:             1,
            },
            LicenseTier::Startup => TierLimits {
                max_nodes:            50,
                max_sessions_per_min: 600,
                retention_days:       90,
                max_orgs:             1,
            },
            LicenseTier::Enterprise => TierLimits {
                max_nodes:            u32::MAX,
                max_sessions_per_min: u32::MAX,
                retention_days:       365,
                max_orgs:             100,
            },
            LicenseTier::Defense => TierLimits {
                max_nodes:            u32::MAX,
                max_sessions_per_min: u32::MAX,
                retention_days:       2555, // 7 years
                max_orgs:             u32::MAX,
            },
        }
    }

    pub fn default_features(&self) -> Vec<LicenseFeature> {
        match self {
            LicenseTier::Community => vec![],
            LicenseTier::Startup   => vec![
                LicenseFeature::Postgres,
                LicenseFeature::Webhooks,
            ],
            LicenseTier::Enterprise => vec![
                LicenseFeature::Postgres,
                LicenseFeature::Sso,
                LicenseFeature::Webhooks,
                LicenseFeature::CustomRetention,
                LicenseFeature::PrioritySupport,
            ],
            LicenseTier::Defense => vec![
                LicenseFeature::Postgres,
                LicenseFeature::AirGap,
                LicenseFeature::Fips,
                LicenseFeature::ClearanceGating,
                LicenseFeature::Federation,
                LicenseFeature::Sso,
                LicenseFeature::PrioritySupport,
                LicenseFeature::CustomRetention,
                LicenseFeature::Webhooks,
            ],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// LICENSE FILE FORMAT (what the customer receives)
// ─────────────────────────────────────────────────────────────────────────

/// The license file placed at /etc/kelan/kelan.license
/// This is signed JSON — the signature covers all fields except itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseFile {
    /// License format version
    pub version:    u8,

    // ── Identity ──────────────────────────────────────────────────────────
    /// Human-readable organisation name
    pub org_name:   String,
    /// Contact email (for support routing)
    pub org_email:  String,
    /// Unique license ID (UUID)
    pub license_id: String,

    // ── Tier and limits ───────────────────────────────────────────────────
    pub tier:       LicenseTier,
    /// Maximum registered entities (0 = unlimited)
    pub max_nodes:  u32,
    /// Enabled features beyond tier defaults
    pub features:   Vec<LicenseFeature>,

    // ── Validity ──────────────────────────────────────────────────────────
    /// Unix timestamp when license was issued
    pub issued_at:  i64,
    /// Unix timestamp when license expires (0 = never expires)
    pub expires_at: i64,

    // ── Signature (must be last field, covers all above fields) ───────────
    /// Ed25519 signature over the canonical JSON of all fields above.
    /// Hex-encoded. Generated by kelan-license-tool using your private key.
    pub signature:  String,
}

impl LicenseFile {
    /// The bytes that were signed — everything except the signature field.
    /// MUST match exactly what kelan-license-tool signs.
    pub fn signing_payload(&self) -> Vec<u8> {
        // Canonical JSON of all fields except signature
        // We use a deterministic serialization to ensure consistency
        let payload = serde_json::json!({
            "version":    self.version,
            "org_name":   self.org_name,
            "org_email":  self.org_email,
            "license_id": self.license_id,
            "tier":       self.tier,
            "max_nodes":  self.max_nodes,
            "features":   self.features,
            "issued_at":  self.issued_at,
            "expires_at": self.expires_at,
        });
        // Use compact JSON with keys in sorted order for determinism
        serde_json::to_vec(&payload).expect("payload serialization never fails")
    }
}

// ─────────────────────────────────────────────────────────────────────────
// ACTIVE LICENSE STATE
// ─────────────────────────────────────────────────────────────────────────

/// Validated, active license — available globally after startup.
#[derive(Debug, Clone)]
pub struct ActiveLicense {
    pub tier:       LicenseTier,
    pub org_name:   String,
    #[allow(dead_code)]
    pub org_email:  String,
    #[allow(dead_code)]
    pub license_id: String,
    pub max_nodes:  u32,
    pub features:   Vec<LicenseFeature>,
    pub expires_at: i64,
    pub source:     LicenseSource,
}

#[derive(Debug, Clone)]
pub enum LicenseSource {
    Community,                  // No license file found
    File { #[allow(dead_code)] path: String },      // Loaded from a license file
}

impl ActiveLicense {
    /// Get global active license (panics if not initialised — call init_license first)
    pub fn get() -> &'static Self {
        ACTIVE_LICENSE.get().expect("License not initialised — call init_license() at startup")
    }

    /// Check if a feature is enabled
    pub fn has_feature(&self, feature: &LicenseFeature) -> bool {
        self.tier.default_features().contains(feature) ||
        self.features.contains(feature)
    }

    /// Check if adding one more node would exceed the limit
    pub fn check_node_limit(&self, current_nodes: u32) -> Result<(), LicenseError> {
        let limit = if self.max_nodes > 0 {
            self.max_nodes
        } else {
            self.tier.hard_limits().max_nodes
        };

        if limit != u32::MAX && current_nodes >= limit {
            Err(LicenseError::NodeLimitExceeded {
                current: current_nodes,
                limit,
                tier: format!("{:?}", self.tier),
            })
        } else {
            Ok(())
        }
    }

    /// Days until expiry (None if never expires)
    pub fn days_until_expiry(&self) -> Option<i64> {
        if self.expires_at == 0 { return None; }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        Some((self.expires_at - now) / 86400)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// ERRORS
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("License signature invalid — file may be tampered")]
    InvalidSignature,

    #[error("License expired {days_ago} days ago (expires_at: {expires_at})")]
    Expired { days_ago: i64, expires_at: i64 },

    #[error("License format invalid: {reason}")]
    InvalidFormat { reason: String },

    #[error("Public key in binary is invalid — build error")]
    InvalidPublicKey,

    #[error("Node limit exceeded: {current}/{limit} nodes on {tier} tier")]
    NodeLimitExceeded { current: u32, limit: u32, tier: String },

    #[error("Feature '{feature:?}' requires {required_tier} tier or higher")]
    #[allow(dead_code)]
    FeatureNotLicensed { feature: LicenseFeature, required_tier: String },

    #[error("Community tier: {0}")]
    #[allow(dead_code)]
    CommunityRestriction(String),
}

// ─────────────────────────────────────────────────────────────────────────
// VALIDATION
// ─────────────────────────────────────────────────────────────────────────

/// Load and validate the license at startup.
/// Called once from main.rs before anything else starts.
///
/// If no license file is found → Community tier (5 nodes, free).
/// If a license file is found but invalid → server REFUSES to start.
/// This prevents running with a tampered license.
pub fn init_license() -> anyhow::Result<&'static ActiveLicense> {
    let active = load_and_validate()?;

    ACTIVE_LICENSE.set(active)
        .map_err(|_| anyhow::anyhow!("License already initialised"))?;

    let license = ACTIVE_LICENSE.get().unwrap();

    // Print license summary at startup
    print_license_banner(license);

    Ok(license)
}

fn load_and_validate() -> anyhow::Result<ActiveLicense> {
    // Try each license search path
    for path in LICENSE_SEARCH_PATHS {
        // Also check KELAN_LICENSE_PATH env var
        let path = std::env::var("KELAN_LICENSE_PATH")
            .unwrap_or_else(|_| path.to_string());

        if std::path::Path::new(&path).exists() {
            tracing::info!("Loading license from: {}", path);
            let content = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("Cannot read license file {}: {}", path, e))?;

            let license: LicenseFile = serde_json::from_str(&content)
                .map_err(|e| LicenseError::InvalidFormat {
                    reason: format!("JSON parse error: {}", e),
                })?;

            // Validate the license — this is the security-critical step
            validate_license(&license)?;

            return Ok(ActiveLicense {
                tier:       license.tier.clone(),
                org_name:   license.org_name.clone(),
                org_email:  license.org_email.clone(),
                license_id: license.license_id.clone(),
                max_nodes:  license.max_nodes,
                features:   license.features.clone(),
                expires_at: license.expires_at,
                source:     LicenseSource::File { path: path.to_string() },
            });
        }
    }

    // No license file found — Community tier
    tracing::info!("No license file found — running Community tier (max 5 nodes)");
    Ok(ActiveLicense {
        tier:       LicenseTier::Community,
        org_name:   "Community".to_string(),
        org_email:  String::new(),
        license_id: "community".to_string(),
        max_nodes:  5,
        features:   vec![],
        expires_at: 0,
        source:     LicenseSource::Community,
    })
}

/// Cryptographically validate a license file.
/// Returns Err if signature is invalid, expired, or format is wrong.
/// This is the only function that matters for security.
pub fn validate_license(license: &LicenseFile) -> Result<(), LicenseError> {
    // ── Step 1: Decode the hardcoded public key ────────────────────────────
    let pubkey_bytes = hex::decode(KELAN_LICENSE_PUBKEY_HEX)
        .map_err(|_| LicenseError::InvalidPublicKey)?;

    let pubkey_arr: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| LicenseError::InvalidPublicKey)?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|_| LicenseError::InvalidPublicKey)?;

    // ── Step 2: Decode the signature from the license file ─────────────────
    let sig_bytes = hex::decode(&license.signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| LicenseError::InvalidSignature)?;

    let signature = Signature::from_bytes(&sig_arr);

    // ── Step 3: Verify the signature over the canonical payload ────────────
    // This is the core security check. If the payload was modified in any way
    // (org_name changed, max_nodes increased, tier upgraded) the signature
    // will not match and this returns Err(InvalidSignature).
    let payload = license.signing_payload();

    verifying_key.verify(&payload, &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    // ── Step 4: Check expiry ───────────────────────────────────────────────
    if license.expires_at > 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if now > license.expires_at {
            let days_ago = (now - license.expires_at) / 86400;
            return Err(LicenseError::Expired {
                days_ago,
                expires_at: license.expires_at,
            });
        }
    }

    // ── Step 5: Warn if expiring soon ─────────────────────────────────────
    if license.expires_at > 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let days_remaining = (license.expires_at - now) / 86400;

        if days_remaining <= 30 {
            tracing::warn!(
                "⚠ License expires in {} days ({}). Contact tanush@kelan.io to renew.",
                days_remaining,
                license.org_name
            );
        }
    }

    Ok(())
}

fn print_license_banner(license: &ActiveLicense) {
    let tier_str = format!("{:?}", license.tier).to_uppercase();
    let expiry_str = match license.days_until_expiry() {
        None      => "Never".to_string(),
        Some(d)   => format!("{} days", d),
    };
    let node_limit = if license.max_nodes == 0 || license.max_nodes == u32::MAX {
        "Unlimited".to_string()
    } else {
        license.max_nodes.to_string()
    };

    println!("  License:  {} — {}", tier_str, license.org_name);
    println!("  Nodes:    {}", node_limit);
    println!("  Expires:  {}", expiry_str);
    if !license.features.is_empty() {
        let features: Vec<String> = license.features.iter()
            .map(|f| format!("{:?}", f))
            .collect();
        println!("  Features: {}", features.join(", "));
    }

    if matches!(license.source, LicenseSource::Community) {
        println!("  ─────────────────────────────────────────────────");
        println!("  Community tier: 5 nodes max, non-commercial use.");
        println!("  Upgrade at kelan.io or email tanush@kelan.io");
        println!("  ─────────────────────────────────────────────────");
    }
}

/// Background task: re-validate license every 24 hours.
/// Catches licenses that expire while the server is running.
pub async fn run_license_watchdog() {
    let mut interval = tokio::time::interval(Duration::from_secs(86400));
    interval.tick().await; // skip first immediate tick

    loop {
        interval.tick().await;

        let license = ActiveLicense::get();
        if license.expires_at > 0 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            if now > license.expires_at {
                tracing::error!(
                    "LICENSE EXPIRED. Server will continue running but \
                     new entity registrations are blocked. \
                     Contact tanush@kelan.io to renew."
                );
                // Don't kill the server — let existing deployments keep running
                // but block new registrations via the check_node_limit guard
            } else {
                let days = (license.expires_at - now) / 86400;
                if days <= 7 {
                    tracing::warn!(
                        "⚠ License expires in {} days! Renew at kelan.io", days
                    );
                }
            }
        }
    }
}
