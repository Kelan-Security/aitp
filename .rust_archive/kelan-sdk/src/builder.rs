use aitp_core::header::IntentCode;
use kelan_crypto::HybridSigningKey;
use crate::error::SdkError;
use crate::session::EstablishedSession;
use crate::client::AitpClient;

#[derive(Default)]
pub struct AitpClientBuilder {
    server: Option<String>,
    intent: Option<IntentCode>,
    identity: Option<HybridSigningKey>,
}

impl AitpClientBuilder {
    pub fn new() -> Self {
        Self {
            server: None,
            intent: None,
            identity: None,
        }
    }

    pub fn server(mut self, addr: &str) -> Self {
        self.server = Some(addr.to_string());
        self
    }

    pub fn intent(mut self, intent: IntentCode) -> Self {
        self.intent = Some(intent);
        self
    }

    pub fn identity(
        mut self, 
        identity: HybridSigningKey
    ) -> Self {
        self.identity = Some(identity);
        self
    }

    pub async fn connect(
        self
    ) -> Result<EstablishedSession, SdkError> {
        let server = self.server
            .ok_or(SdkError::Protocol(
                "server address required".into()
            ))?;
        let intent = self.intent
            .ok_or(SdkError::Protocol(
                "intent required".into()
            ))?;
        let identity = self.identity
            .ok_or(SdkError::Protocol(
                "identity required".into()
            ))?;

        AitpClient::connect(
            &server, intent, &identity
        ).await
    }
}
