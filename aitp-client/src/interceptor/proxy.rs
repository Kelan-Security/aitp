// Kelan Security Client Agent — interceptor/proxy.rs
// SOCKS5 local proxy — cross-platform, primary interception mode.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::AgentConfig;
use crate::handshake::{self, AitpHandshake, IntentCode};
use crate::identity::EntityIdentity;
use crate::session::SessionTable;

/// Global quarantine flag — set by the command channel
pub static QUARANTINE_FLAG: AtomicBool = AtomicBool::new(false);

pub async fn run_socks5_proxy(
    config: Arc<AgentConfig>,
    identity: Arc<EntityIdentity>,
    sessions: SessionTable,
) -> anyhow::Result<()> {
    let addr = format!("127.0.0.1:{}", config.interception.proxy_port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("SOCKS5 proxy listening on {}", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let config = Arc::clone(&config);
        let identity = Arc::clone(&identity);
        let sessions = sessions.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, config, identity, sessions).await {
                tracing::debug!(peer = %peer_addr, error = %e, "SOCKS5 connection error");
            }
        });
    }
}

async fn handle_connection(
    mut client: TcpStream,
    config: Arc<AgentConfig>,
    identity: Arc<EntityIdentity>,
    sessions: SessionTable,
) -> anyhow::Result<()> {
    // Check quarantine
    if QUARANTINE_FLAG.load(Ordering::SeqCst) {
        socks5_reply_refused(&mut client).await?;
        return Ok(());
    }

    // ── SOCKS5 negotiation ──
    let (target_host, target_port) = socks5_negotiate(&mut client).await?;

    // ── Skip excluded ports/hosts ──
    if config.interception.exclude_ports.contains(&target_port)
        || config
            .interception
            .exclude_hosts
            .iter()
            .any(|h| h == &target_host)
    {
        return forward_direct(&mut client, &target_host, target_port).await;
    }

    // ── Determine intent from destination ──
    let intent = handshake::infer_intent(&target_host, target_port);

    tracing::debug!(
        target = %format!("{}:{}", target_host, target_port),
        intent = %intent,
        "evaluating connection"
    );

    // ── Perform AITP handshake with Intelligence Core ──
    let dest_entity_id = "0".repeat(64); // Destination entity (IC resolves the real target)
    let handshake_result = async {
        let hs = AitpHandshake::new(
            Arc::clone(&identity),
            &config.server.address,
            config.server.udp_port,
        )
        .await?;
        hs.establish(&dest_entity_id, intent).await
    }
    .await;

    match handshake_result {
        Ok(permit) => {
            // Session granted — register and forward
            let session_id = permit.session_id;
            sessions.insert(session_id, permit).await;
            socks5_reply_success(&mut client).await?;

            let mut server = TcpStream::connect(format!("{}:{}", target_host, target_port)).await?;
            let result = bidirectional_proxy(&mut client, &mut server).await;

            sessions.remove(session_id).await;
            result
        }
        Err(e) => {
            if config.interception.fail_closed {
                tracing::warn!(
                    target = %format!("{}:{}", target_host, target_port),
                    error = %e,
                    "connection denied by Kelan Security"
                );
                socks5_reply_refused(&mut client).await?;
                Ok(())
            } else {
                tracing::warn!(
                    target = %format!("{}:{}", target_host, target_port),
                    error = %e,
                    "fail-open: allowing connection despite IC error"
                );
                forward_direct(&mut client, &target_host, target_port).await
            }
        }
    }
}

/// SOCKS5 protocol implementation (RFC 1928)
async fn socks5_negotiate(stream: &mut TcpStream) -> anyhow::Result<(String, u16)> {
    // 1. Client greeting
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    let _version = buf[0]; // Should be 0x05
    let n_methods = buf[1] as usize;
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;

    // 2. Server choice: no auth (method 0x00)
    stream.write_all(&[0x05, 0x00]).await?;

    // 3. Client request
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let _cmd = header[1]; // 0x01 = CONNECT
    let atyp = header[3];

    let host = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            // Domain name
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => anyhow::bail!("Unsupported SOCKS5 address type: {}", atyp),
    };

    let port = stream.read_u16().await?;
    Ok((host, port))
}

async fn socks5_reply_success(stream: &mut TcpStream) -> anyhow::Result<()> {
    // VER=5, REP=0 (success), RSV=0, ATYP=1 (IPv4), BND.ADDR=0, BND.PORT=0
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn socks5_reply_refused(stream: &mut TcpStream) -> anyhow::Result<()> {
    // Connection refused: REP=0x05
    stream
        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn bidirectional_proxy(client: &mut TcpStream, server: &mut TcpStream) -> anyhow::Result<()> {
    let (mut cr, mut cw) = client.split();
    let (mut sr, mut sw) = server.split();

    tokio::select! {
        result = tokio::io::copy(&mut cr, &mut sw) => { result?; }
        result = tokio::io::copy(&mut sr, &mut cw) => { result?; }
    };
    Ok(())
}

async fn forward_direct(client: &mut TcpStream, host: &str, port: u16) -> anyhow::Result<()> {
    socks5_reply_success(client).await?;
    let mut server = TcpStream::connect(format!("{}:{}", host, port)).await?;
    tokio::io::copy_bidirectional(client, &mut server).await?;
    Ok(())
}

/// Infer IntentCode from destination host/port (re-exported from handshake)
#[allow(dead_code)]
pub fn infer_intent(host: &str, port: u16) -> IntentCode {
    handshake::infer_intent(host, port)
}
