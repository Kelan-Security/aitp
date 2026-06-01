use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    pub fn derive(
        shared_secret: &[u8],
        session_id: &[u8],
    ) -> Result<Self, crate::CryptoError> {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(shared_secret);
        hasher.update(session_id);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Ok(SessionKey(key))
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
