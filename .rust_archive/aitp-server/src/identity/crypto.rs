#![allow(dead_code)]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Generate an Ed25519 keypair. Returns (signing_key_bytes, verifying_key_bytes).
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key.to_bytes(), verifying_key.to_bytes())
}

/// Compute EntityID = SHA-256(Ed25519 public key).
pub fn entity_id_from_pubkey(pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Compute EntityID from hex-encoded public key string.
pub fn entity_id_from_pubkey_hex(pubkey_hex: &str) -> Option<String> {
    let bytes = hex::decode(pubkey_hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(entity_id_from_pubkey(&arr))
}

/// Sign a message with the given signing key bytes.
pub fn sign_message(signing_key_bytes: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let sig = signing_key.sign(message);
    sig.to_bytes()
}

/// Verify a signature against a public key.
pub fn verify_signature(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (sk, pk) = generate_keypair();
        assert_ne!(sk, [0u8; 32]);
        assert_ne!(pk, [0u8; 32]);
    }

    #[test]
    fn test_entity_id_deterministic() {
        let (_, pk) = generate_keypair();
        let id1 = entity_id_from_pubkey(&pk);
        let id2 = entity_id_from_pubkey(&pk);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_entity_id_from_hex() {
        let (_, pk) = generate_keypair();
        let hex_pk = hex::encode(pk);
        let id_from_bytes = entity_id_from_pubkey(&pk);
        let id_from_hex = entity_id_from_pubkey_hex(&hex_pk).unwrap();
        assert_eq!(id_from_bytes, id_from_hex);
    }

    #[test]
    fn test_sign_verify() {
        let (sk, pk) = generate_keypair();
        let msg = b"test message for signing";
        let sig = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &sig));
    }

    #[test]
    fn test_sign_verify_wrong_key() {
        let (sk, _) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let msg = b"test message";
        let sig = sign_message(&sk, msg);
        assert!(!verify_signature(&pk2, msg, &sig));
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let (sk, pk) = generate_keypair();
        let sig = sign_message(&sk, b"original");
        assert!(!verify_signature(&pk, b"tampered", &sig));
    }

    #[test]
    fn test_entity_id_from_hex_invalid() {
        assert!(entity_id_from_pubkey_hex("not_hex").is_none());
        assert!(entity_id_from_pubkey_hex("deadbeef").is_none()); // too short
    }
}
