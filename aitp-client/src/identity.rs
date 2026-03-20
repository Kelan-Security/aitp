// Kelan Security Client Agent — identity.rs
// Ed25519 keypair generation with secure file-based storage.

use anyhow::Result;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Directory for storing identity keys
const KEY_DIR: &str = "/etc/kelan";
const KEY_FILE: &str = "agent-identity.key";

pub struct EntityIdentity {
    /// SHA-256(public_key) — 32 bytes, stable identifier
    pub entity_id: [u8; 32],
    /// Public key — shared with Intelligence Core during enrolment
    pub public_key_bytes: [u8; 32],
    /// Signing key — NEVER leaves this process
    signing_key: SigningKey,
}

impl EntityIdentity {
    /// Load from disk, or generate new keypair if first run.
    pub fn load_or_generate(custom_dir: Option<&std::path::Path>) -> Result<Self> {
        let dir = custom_dir.map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from(KEY_DIR));
        let key_path = dir.join(KEY_FILE);

        let signing_key = if key_path.exists() {
            // Load existing key
            let key_bytes = std::fs::read(&key_path)?;
            if key_bytes.len() != 32 {
                anyhow::bail!("Invalid key file length — expected 32 bytes, got {}", key_bytes.len());
            }
            let key_arr: [u8; 32] = key_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key bytes"))?;
            tracing::info!("Loaded Ed25519 keypair from {:?}", key_path);
            SigningKey::from_bytes(&key_arr)
        } else {
            // Generate new keypair
            tracing::info!("Generating new Ed25519 keypair for this device");
            let key = SigningKey::generate(&mut OsRng);

            // Store on disk
            if let Some(parent) = key_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&key_path, key.to_bytes())?;

            // Set restrictive permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }

            tracing::info!("Private key stored at {:?}", key_path);
            key
        };

        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();

        // EntityID = SHA-256(public_key)
        let mut hasher = Sha256::new();
        hasher.update(public_key_bytes);
        let entity_id: [u8; 32] = hasher.finalize().into();

        Ok(Self {
            entity_id,
            public_key_bytes,
            signing_key,
        })
    }

    /// Sign arbitrary data (used in handshake phases 1-3)
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing_key.sign(data).to_bytes()
    }

    /// EntityID as lowercase hex string
    pub fn entity_id_hex(&self) -> String {
        hex::encode(self.entity_id)
    }

    /// Short display form for logs (first 16 hex chars)
    pub fn short_id(&self) -> String {
        hex::encode(&self.entity_id[..8])
    }

    /// Public key as hex (sent to IC during enrolment)
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes)
    }

    /// Delete the stored key (for reset-keys command)
    pub fn delete_stored_key() -> Result<()> {
        let key_path = std::path::Path::new(KEY_DIR).join(KEY_FILE);
        if key_path.exists() {
            std::fs::remove_file(&key_path)?;
        }
        Ok(())
    }
}
