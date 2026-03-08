use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FederatedTrustToken {
    pub version: u8,
    pub source_org_id: String,
    pub source_org_name: String,
    pub source_entity_id: String,
    pub dest_org_id: String,
    pub allowed_intents: Vec<String>,
    pub trust_floor: u8, // minimum score required for this federation
    pub issued_at: i64,
    pub expires_at: i64,
    pub policy_hash: String, // SHA-256 of the policy terms agreed upon
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FederatedTrustTokenSigned {
    pub claims: FederatedTrustToken,
    #[serde(with = "hex_sig")]
    pub signature: [u8; 64], // Ed25519 over claims JSON
    pub signing_key_id: String, // which root key signed this
}

mod hex_sig {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let mut bytes = [0u8; 64];
        let decoded = hex::decode(s).map_err(serde::de::Error::custom)?;
        if decoded.len() != 64 {
            return Err(serde::de::Error::custom("invalid signature length"));
        }
        bytes.copy_from_slice(&decoded);
        Ok(bytes)
    }
}
