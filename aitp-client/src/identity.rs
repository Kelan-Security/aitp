// AITP Client Agent — identity.rs
// Ed25519 keypair generation and secure storage management.

use anyhow::{Context, Result};
use ed25519_dalek::{SecretKey, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::config::ClientConfig;

pub struct EntityIdentity {
    pub entity_id: [u8; 32],
    pub public_key: [u8; 32],
    signing_key: SigningKey,
}

impl EntityIdentity {
    /// Generate a new keypair or load an existing one from disk.
    pub fn generate_or_load(config: &ClientConfig) -> Result<Self> {
        let key_path = Self::key_path(config);

        let signing_key = if key_path.exists() {
            // Load existing key
            let bytes = std::fs::read(&key_path)
                .with_context(|| format!("Failed to read key file: {:?}", key_path))?;
            if bytes.len() != 32 {
                anyhow::bail!("Invalid key file length — expected 32 bytes");
            }
            let secret: SecretKey = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid secret key bytes"))?;
            SigningKey::from_bytes(&secret)
        } else {
            // Generate new keypair
            let key = SigningKey::generate(&mut OsRng);
            Self::save_key(&key_path, &key)?;
            tracing::info!("Generated new Ed25519 keypair at {:?}", key_path);
            key
        };

        let public_key: VerifyingKey = signing_key.verifying_key();
        let public_key_bytes = public_key.to_bytes();

        // entity_id = SHA-256(public_key)
        let entity_id: [u8; 32] = Sha256::digest(public_key_bytes).into();

        Ok(Self {
            entity_id,
            public_key: public_key_bytes,
            signing_key,
        })
    }

    /// Sign arbitrary data using the entity's private key.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing_key.sign(data).to_bytes()
    }

    /// Return entity ID as a short hex string suitable for display.
    pub fn entity_id_hex(&self) -> String {
        hex::encode(&self.entity_id[..8]) + "..."
    }

    /// Return entity ID as full hex string.
    pub fn entity_id_full_hex(&self) -> String {
        hex::encode(self.entity_id)
    }

    /// Return public key as hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    fn key_path(config: &ClientConfig) -> PathBuf {
        let config_path = crate::config::ClientConfig::default_config_path();
        let dir = config_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        // Use entity_name to namespace keys if set
        let name = if config.agent.entity_name.is_empty() {
            "identity".to_string()
        } else {
            format!("identity_{}", config.agent.entity_name.replace(' ', "_"))
        };

        dir.join(format!("{}.key", name))
    }

    fn save_key(path: &PathBuf, key: &SigningKey) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, key.to_bytes())?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }
}
