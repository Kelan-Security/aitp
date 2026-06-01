use kelan_crypto::session::SessionKey;
use aitp_core::header::IntentCode;

pub struct EstablishedSession {
    pub session_id: uuid::Uuid,
    pub session_key: SessionKey,
    pub intent_code: IntentCode,
    pub trust_score: f64,
    pub verdict: String, // "Allow" / "Monitor"
}
