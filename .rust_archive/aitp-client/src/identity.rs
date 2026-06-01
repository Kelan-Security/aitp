use kelan_crypto::{CryptoAlgorithm, HybridEntityIdentity};

pub use kelan_crypto::HybridEntityIdentity as EntityIdentity;

/// Load or generate the device's hybrid PQ identity.
/// Called once at daemon startup.
pub fn load_or_generate() -> anyhow::Result<HybridEntityIdentity> {
    HybridEntityIdentity::load_or_generate()
}

/// Print identity summary for `kelan-agent status`
pub fn print_identity_summary(identity: &HybridEntityIdentity) {
    println!("Entity ID:   {}", identity.entity_id_hex());
    println!("Short ID:    {}", identity.short_id());
    println!("Algorithm:   {:?}", identity.algorithm);
    println!("Public key:  {} bytes", identity.public_key_bytes().len());
    match identity.algorithm {
        CryptoAlgorithm::HybridPQ => {
            println!("Crypto mode: Hybrid (Ed25519 + ML-DSA-65 / FIPS 204)")
        }
        CryptoAlgorithm::Classical => println!("Crypto mode: Classical (Ed25519 only)"),
        CryptoAlgorithm::PostQuantum => println!("Crypto mode: Post-quantum only (ML-DSA-65)"),
    }
}
