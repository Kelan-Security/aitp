// Kernex Client Agent — handshake.rs
// UDP-based AITP handshake with the Intelligence Core.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngCore;

use crate::identity::EntityIdentity;

#[derive(Debug, Clone)]
pub struct SessionPermit {
    pub session_id: u64,
    pub trust_score: u8,
    pub verdict: Verdict,
    pub intent: IntentCode,
    pub expires_at: std::time::Instant,
    pub ai_reasoning: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Allow,
    Monitor,
    Deny,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Allow => write!(f, "Allow"),
            Verdict::Monitor => write!(f, "Monitor"),
            Verdict::Deny => write!(f, "Deny"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
#[allow(dead_code)]
pub enum IntentCode {
    ModelInference  = 0x0001,
    DataSync        = 0x0002,
    ControlSignal   = 0x0003,
    Telemetry       = 0x0004,
    AgentCoordinate = 0x0005,
    FileTransfer    = 0x0006,
    Heartbeat       = 0x0007,
    Unknown         = 0x00FF,
}

impl std::fmt::Display for IntentCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentCode::ModelInference  => write!(f, "ModelInference"),
            IntentCode::DataSync        => write!(f, "DataSync"),
            IntentCode::ControlSignal   => write!(f, "ControlSignal"),
            IntentCode::Telemetry       => write!(f, "Telemetry"),
            IntentCode::AgentCoordinate => write!(f, "AgentCoordinate"),
            IntentCode::FileTransfer    => write!(f, "FileTransfer"),
            IntentCode::Heartbeat       => write!(f, "Heartbeat"),
            IntentCode::Unknown         => write!(f, "Unknown"),
        }
    }
}

/// AITP handshake client — talks to the Intelligence Core over UDP.
pub struct AitpHandshake {
    identity: Arc<EntityIdentity>,
    server_addr: std::net::SocketAddr,
    socket: Arc<tokio::net::UdpSocket>,
}

impl AitpHandshake {
    pub async fn new(
        identity: Arc<EntityIdentity>,
        server_host: &str,
        server_port: u16,
    ) -> anyhow::Result<Self> {
        let server_addr: std::net::SocketAddr =
            format!("{}:{}", server_host, server_port).parse()
                .map_err(|e| anyhow::anyhow!("Invalid server address: {}", e))?;

        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Self {
            identity,
            server_addr,
            socket: Arc::new(socket),
        })
    }

    /// Execute the full 5-phase handshake.
    /// Returns SessionPermit on Allow/Monitor, Err on Deny or timeout.
    pub async fn establish(
        &self,
        dest_entity_id: &str,
        intent: IntentCode,
    ) -> anyhow::Result<SessionPermit> {
        let timeout = Duration::from_millis(5000);
        tokio::time::timeout(timeout, self.handshake_inner(dest_entity_id, intent))
            .await
            .map_err(|_| anyhow::anyhow!("Handshake timeout (>5000ms)"))?
    }

    async fn handshake_inner(
        &self,
        dest_entity_id: &str,
        intent: IntentCode,
    ) -> anyhow::Result<SessionPermit> {
        let session_id = rand::random::<u64>();
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?.as_micros() as u64;

        // ── Phase 1: AITP_HELLO (SYN)
        let mut hello = Vec::with_capacity(128);
        hello.push(3u8);          // version
        hello.push(0x01u8);       // flags: SYN
        hello.extend_from_slice(&(intent as u16).to_be_bytes());
        hello.extend_from_slice(&session_id.to_be_bytes());
        hello.extend_from_slice(&timestamp.to_be_bytes());
        hello.extend_from_slice(&nonce);
        hello.extend_from_slice(&self.identity.entity_id);
        hello.extend_from_slice(&parse_entity_id(dest_entity_id)?);

        let signature = self.identity.sign(&hello);
        hello.extend_from_slice(&signature);

        self.socket.send_to(&hello, self.server_addr).await?;
        tracing::debug!(session_id, "Phase 1: HELLO sent");

        // ── Phase 2: Receive IDENTITY_CHALLENGE, send response
        let challenge = self.recv_challenge(session_id).await?;
        tracing::debug!(session_id, "Phase 2: Challenge received");

        let challenge_sig = self.identity.sign(&challenge);
        let mut response = Vec::with_capacity(128);
        response.push(0x02u8); // type: challenge_response
        response.extend_from_slice(&session_id.to_be_bytes());
        response.extend_from_slice(&challenge_sig);
        response.extend_from_slice(&self.identity.public_key_bytes);

        self.socket.send_to(&response, self.server_addr).await?;
        tracing::debug!(session_id, "Phase 2: Challenge response sent");

        // ── Phase 3: INTENT_DECLARE
        let mut intent_bytes = Vec::new();
        intent_bytes.extend_from_slice(&session_id.to_be_bytes());
        intent_bytes.extend_from_slice(&(intent as u16).to_be_bytes());
        let intent_sig = self.identity.sign(&intent_bytes);

        let mut intent_packet = Vec::with_capacity(80);
        intent_packet.push(0x03u8); // type: intent_declare
        intent_packet.extend_from_slice(&session_id.to_be_bytes());
        intent_packet.extend_from_slice(&(intent as u16).to_be_bytes());
        intent_packet.extend_from_slice(&intent_sig);

        self.socket.send_to(&intent_packet, self.server_addr).await?;
        tracing::debug!(session_id, "Phase 3: Intent declared");

        // ── Phase 4+5: Wait for AI evaluation + verdict
        let permit = self.recv_verdict(session_id, intent).await?;
        tracing::debug!(
            session_id,
            score = permit.trust_score,
            verdict = %permit.verdict,
            "Phase 4+5: Verdict received"
        );

        match permit.verdict {
            Verdict::Deny => {
                anyhow::bail!(
                    "Session denied by Intelligence Core. Score: {}/255. Reason: {}",
                    permit.trust_score,
                    permit.ai_reasoning
                )
            }
            _ => Ok(permit),
        }
    }

    async fn recv_challenge(&self, session_id: u64) -> anyhow::Result<[u8; 32]> {
        let mut buf = [0u8; 512];
        loop {
            let (n, _) = self.socket.recv_from(&mut buf).await?;
            if n >= 41 && buf[0] == 0x12 {
                // Parse challenge: type(1) + session_id(8) + challenge(32)
                let recv_sid = u64::from_be_bytes(buf[1..9].try_into()?);
                if recv_sid == session_id {
                    let mut challenge = [0u8; 32];
                    challenge.copy_from_slice(&buf[9..41]);
                    return Ok(challenge);
                }
            }
        }
    }

    async fn recv_verdict(
        &self,
        session_id: u64,
        intent: IntentCode,
    ) -> anyhow::Result<SessionPermit> {
        let mut buf = [0u8; 1024];
        loop {
            let (n, _) = self.socket.recv_from(&mut buf).await?;
            if n >= 12 && (buf[0] == 0x20 || buf[0] == 0x21) {
                // 0x20 = GRANT, 0x21 = REJECT
                let recv_sid = u64::from_be_bytes(buf[1..9].try_into()?);
                if recv_sid == session_id {
                    let trust_score = buf[9];
                    let verdict = if buf[0] == 0x20 {
                        if trust_score >= 128 { Verdict::Allow } else { Verdict::Monitor }
                    } else {
                        Verdict::Deny
                    };

                    // Parse optional reasoning string
                    let reasoning_len = if n >= 12 {
                        u16::from_be_bytes(buf[10..12].try_into()?) as usize
                    } else {
                        0
                    };
                    let ai_reasoning = if reasoning_len > 0 && n >= 12 + reasoning_len {
                        String::from_utf8_lossy(&buf[12..12 + reasoning_len]).to_string()
                    } else {
                        String::new()
                    };

                    return Ok(SessionPermit {
                        session_id,
                        trust_score,
                        verdict,
                        intent,
                        expires_at: std::time::Instant::now() + Duration::from_secs(3600),
                        ai_reasoning,
                    });
                }
            }
        }
    }
}

fn parse_entity_id(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| anyhow::anyhow!("Invalid entity ID format (expected 64-char hex)"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Entity ID must be 32 bytes (64 hex chars)"))
}

/// Infer IntentCode from destination host/port.
pub fn infer_intent(host: &str, port: u16) -> IntentCode {
    match port {
        // Common ML/AI inference endpoints
        8080 | 8081 | 8082 => IntentCode::ModelInference,
        // Database ports
        5432 | 3306 | 27017 | 6379 => IntentCode::DataSync,
        // Metrics/telemetry
        9090 | 9091 | 4317 | 4318 => IntentCode::Telemetry,
        // HTTPS/HTTP — contextual
        443 | 8443 => {
            if host.contains("api.") || host.contains("inference") {
                IntentCode::ModelInference
            } else {
                IntentCode::DataSync
            }
        }
        _ => IntentCode::Unknown,
    }
}
