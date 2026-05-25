pub mod agent;
pub mod ai;
pub mod api;
pub mod auth;
pub mod budget;
pub mod config;
pub mod crypto;
pub mod db;
pub mod enforcement;
pub mod error;
pub mod identity;
pub mod license;
pub mod metrics;
pub mod persistence;
pub mod protocol;
pub mod sentinel;
pub mod state;
pub mod tls;
pub mod trust;
pub mod ws;

use axum::{extract::Host, http::{Uri, HeaderValue, header}, response::Redirect, routing::get, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration, Instant};
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use chrono::Timelike as _;

/// Spawns the server components (HTTP/HTTPS and UDP) based on the provided configuration.
pub async fn run_server(app_config: config::AppConfig) -> anyhow::Result<()> {
    tracing::info!("Starting Kelan Intelligence Core...");

    let db_pool = match db::DbPool::connect(&app_config.db_path).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!("Failed to connect to database at {}: {:?}", app_config.db_path, e);
            anyhow::bail!("Database connection failed");
        }
    };

    let (sentinel_tx, sentinel_rx) = tokio::sync::mpsc::channel::<sentinel::SentinelEvent>(10_000);
    let sentinel_instance = Arc::new(sentinel::SentinelState::new());
    let _ = sentinel_instance.load_from_db(&db_pool, "system").await;

    let ollama_client = Arc::new(ai::OllamaClient::new(&app_config.ollama_endpoint));
    let trust_engine = trust::HybridTrustEngine::new(
        &app_config.ollama_endpoint,
        &app_config.ollama_model,
        app_config.ollama_timeout_secs,
        app_config.trust_alpha,
        &app_config.trust_mode,
    );

    let memory_budget = Arc::new(budget::MemoryBudget::new());
    let enforcer = enforcement::init_enforcer(&app_config.xdp_interface).await?;
    let enforcer = Arc::new(enforcer);

    let server_identity = crypto::HybridEntityIdentity::load_or_generate()
        .expect("Failed to load or generate server identity");
    let server_identity = Arc::new(server_identity);

    let (verdict_tx, _) = tokio::sync::broadcast::channel(1000);

    let app_state = Arc::new(state::AppState {
        db: db_pool,
        hub: ws::WsHub::new(memory_budget.clone(), server_identity.clone()),
        config: app_config.clone(),
        start_time: Instant::now(),
        sentinel: sentinel_instance.clone(),
        sentinel_tx,
        trust_engine,
        memory_budget,
        enforcer,
        server_identity: server_identity.clone(),
        ollama_client,
        sessions: tokio::sync::RwLock::new(crate::protocol::session::SessionManager::new()),
        handshakes: tokio::sync::RwLock::new(crate::protocol::handshake::HandshakeManager::new()),
        verdict_tx,
    });

    // ── Background Tasks ──────────────────────────────────────────────────────
    if app_config.sentinel_enabled {
        let s = app_state.clone();
        tokio::spawn(async move {
            sentinel::run_event_driven(s, sentinel_rx).await;
        });
    }

    {
        let udp_port = app_config.udp_port;
        let state_for_udp = app_state.clone();
        tokio::spawn(async move {
            if let Err(e) = start_udp_listener(udp_port, state_for_udp).await {
                tracing::error!("FATAL: UDP listener died: {}", e);
            }
        });
    }

    {
        let enforcer = app_state.enforcer.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                if let Err(e) = enforcer.cleanup_expired_sessions().await {
                    tracing::warn!("eBPF session cleanup error: {}", e);
                }
            }
        });
    }

    let app = build_app(app_state.clone(), &app_config);

    match tls::detect_mode(&app_config) {
        tls::ServerMode::Http { port } => {
            let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
            tracing::info!("Listening on http://{}", addr);
            axum_server::bind(addr).serve(app.into_make_service()).await?;
        }
        tls::ServerMode::Https { http_port, https_port, cert, key } => {
            let rustls_config = tls::load_rustls_config(&cert, &key).await?;
            let https_addr: SocketAddr = format!("0.0.0.0:{}", https_port).parse()?;

            let redirect_app = Router::new().fallback(|Host(host): Host, uri: Uri| async move {
                let target = format!("https://{}{}", host, uri);
                Redirect::permanent(&target)
            });

            tokio::spawn(async move {
                let http_addr: SocketAddr = format!("0.0.0.0:{}", http_port).parse().expect("Invalid address");
                let _ = axum_server::bind(http_addr).serve(redirect_app.into_make_service()).await;
            });

            tracing::info!("Listening on https://{}", https_addr);
            axum_server::bind_rustls(https_addr, rustls_config).serve(app.into_make_service()).await?;
        }
    }

    Ok(())
}

pub async fn run_with_listener(listener: std::net::TcpListener) -> anyhow::Result<()> {
    tracing::info!("Starting Kelan Intelligence Core (Test)...");
    
    // Initialise license system (required for stats and node limits)
    let _ = crate::license::init_license();

    let mut app_config = config::AppConfig::from_env();
    app_config.db_path = "sqlite::memory:".to_string();

    let db_pool = match db::DbPool::connect(&app_config.db_path).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!("Failed to connect to test database: {:?}", e);
            anyhow::bail!("Database connection failed");
        }
    };

    let (sentinel_tx, sentinel_rx) = tokio::sync::mpsc::channel::<sentinel::SentinelEvent>(10_000);
    let sentinel_instance = Arc::new(sentinel::SentinelState::new());
    let _ = sentinel_instance.load_from_db(&db_pool, "system").await;

    let ollama_client = Arc::new(ai::OllamaClient::new(&app_config.ollama_endpoint));
    let trust_engine = trust::HybridTrustEngine::new(
        &app_config.ollama_endpoint,
        &app_config.ollama_model,
        app_config.ollama_timeout_secs,
        app_config.trust_alpha,
        &app_config.trust_mode,
    );

    let memory_budget = Arc::new(budget::MemoryBudget::new());
    let enforcer = enforcement::init_enforcer(&app_config.xdp_interface).await?;
    let enforcer = Arc::new(enforcer);

    let server_identity = crypto::HybridEntityIdentity::load_or_generate()
        .expect("Failed to load or generate server identity");
    let server_identity = Arc::new(server_identity);

    let (verdict_tx, _) = tokio::sync::broadcast::channel(1000);

    let app_state = Arc::new(state::AppState {
        db: db_pool,
        hub: ws::WsHub::new(memory_budget.clone(), server_identity.clone()),
        config: app_config.clone(),
        start_time: Instant::now(),
        sentinel: sentinel_instance.clone(),
        sentinel_tx,
        trust_engine,
        memory_budget,
        enforcer,
        server_identity: server_identity.clone(),
        ollama_client,
        sessions: tokio::sync::RwLock::new(crate::protocol::session::SessionManager::new()),
        handshakes: tokio::sync::RwLock::new(crate::protocol::handshake::HandshakeManager::new()),
        verdict_tx,
    });

    if app_config.sentinel_enabled {
        let s = app_state.clone();
        tokio::spawn(async move {
            sentinel::run_event_driven(s, sentinel_rx).await;
        });
    }

    let app = build_app(app_state.clone(), &app_config);
    
    listener.set_nonblocking(true)?;
    let tokio_listener = tokio::net::TcpListener::from_std(listener)?;
    
    axum::serve(tokio_listener, app.into_make_service()).await?;

    Ok(())
}

pub fn build_app(state: Arc<state::AppState>, _config: &config::AppConfig) -> Router {
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    
    Router::new()
        .merge(api::router())
        .route("/ws", get(ws::ws_handler))
        .route("/ws/agent", get(api::agentic::ws_agentic_handler))
        .route("/metrics", get(metrics::metrics_handler))
        .route("/health", get(|| async { axum::Json(serde_json::json!({"status":"ok","version":"0.3.0"})) }))
        .with_state(state)
        .fallback_service(
            tower_http::services::ServeDir::new("static")
                .fallback(tower_http::services::ServeFile::new("static/index.html")),
        )
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
        .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::if_not_present(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000; includeSubDomains")))
        .layer(SetResponseHeaderLayer::overriding(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; connect-src 'self' wss:")))
}

async fn start_udp_listener(port: u16, state: Arc<state::AppState>) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", port)).await?);
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer_addr) = socket.recv_from(&mut buf).await?;
        let packet_data = buf[..len].to_vec();
        let sock = Arc::clone(&socket);
        let st = state.clone();
        tokio::spawn(async move {
            let _ = process_aitp_packet(packet_data, peer_addr, sock, st).await;
        });
    }
}

async fn process_aitp_packet(
    bytes: Vec<u8>,
    peer_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    state: Arc<state::AppState>,
) -> anyhow::Result<()> {
    use crate::protocol::{AitpHeaderV4, FLAG_SYN, FLAG_ACK, FLAG_FIN};
    use crate::trust::SessionContext;

    let header = AitpHeaderV4::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("AITP parse error: {}", e))?;

    if header.is_syn() {
        let session_id = header.session_id;
        let intent_code = crate::protocol::IntentCode::from_u16(header.intent);
        let source_entity_id = hex::encode(header.source_id());

        let syn_ack = AitpHeaderV4 {
            version: 4,
            flags: FLAG_SYN | FLAG_ACK,
            intent: header.intent,
            session_id,
            timestamp: chrono::Utc::now().timestamp_micros() as u64,
            nonce: rand::random::<[u8; 12]>(),
            algorithm: 2,
            source_pk: state.server_identity.public_key_bytes().to_vec(),
            dest_id: header.source_id(),
            signature: vec![],
            payload_len: 0,
        };

        socket.send_to(&syn_ack.to_bytes(), peer_addr).await?;

        if intent_code != crate::protocol::IntentCode::Unknown {
            let ctx = SessionContext {
                source_entity_id: source_entity_id.clone(),
                org_id: "system".to_string(),
                source_entity_type: "Agent".to_string(),
                source_department: None,
                source_clearance: 0,
                dest_entity_id: hex::encode(header.dest_id),
                dest_entity_type: "Server".to_string(),
                intent: intent_code.as_str().to_string(),
                entity_age_hours: 0.0,
                session_count_24h: 0,
                avg_trust_score: 128.0,
                known_peer: false,
                behavioral_flags: vec![],
                time_of_day_hour: chrono::Utc::now().hour() as u8,
            };

            let result = state.trust_engine.evaluate(&ctx).await;
            
            let source_id_bytes: [u8; 32] = {
                let decoded = hex::decode(&source_entity_id).unwrap_or_else(|_| vec![0; 32]);
                let mut arr = [0u8; 32];
                let len = decoded.len().min(32);
                arr[..len].copy_from_slice(&decoded[..len]);
                arr
            };
            
            let verdict_byte = match result.verdict {
                crate::trust::TrustVerdict::Allow => 1u8,
                crate::trust::TrustVerdict::Monitor => 2u8,
                crate::trust::TrustVerdict::Deny => 0u8,
            };

            // Wire HandshakeManager dead code logic during handshake completion
            let mut hs_mgr = state.handshakes.write().await;
            let _ = hs_mgr.begin(&header);
            
            let current_phase = if let Ok(ctx) = hs_mgr.complete_trust_eval(session_id, result.trust_score, result.verdict.as_str()) {
                ctx.phase
            } else {
                crate::protocol::handshake::HandshakePhase::AwaitingSynAck
            };

            crate::enforcement::register_kernel_session(
                &state.enforcer,
                session_id,
                &source_id_bytes,
                &header.dest_id,
                header.intent,
                result.trust_score,
                verdict_byte,
                [0u8; 32],
                current_phase,
            ).await;

            let _ = hs_mgr.get(session_id);
            let _ = hs_mgr.remove(session_id);

            // Create session in AppState SessionManager
            let mut sess_mgr = state.sessions.write().await;
            sess_mgr.create(crate::protocol::session::ActiveSession {
                id: session_id.to_string(),
                source_entity_id: source_entity_id.clone(),
                dest_entity_id: hex::encode(header.dest_id),
                intent: intent_code,
                trust_score: result.trust_score,
                verdict: result.verdict.as_str().to_string(),
                bytes_tx: 0,
                bytes_rx: 0,
                started_at: chrono::Utc::now().timestamp(),
                last_activity: chrono::Utc::now().timestamp(),
                anomaly_flags: vec![],
                session_key: None,
            });
        }
    } else if header.has_flag(FLAG_FIN) {
        let mut sess_mgr = state.sessions.write().await;
        let _ = sess_mgr.remove(&header.session_id.to_string());
        let prefix: [u8; 8] = header.dest_id[..8].try_into().unwrap_or([0u8; 8]);
        let _ = state.enforcer.revoke_entity(&prefix).await;
    }

    Ok(())
}

pub async fn cmd_generate_token(
    org_id: &str,
    org_name: &str,
    email: &str,
    role: &str,
) -> anyhow::Result<()> {
    let config = crate::auth::TokenConfig::from_env().expect("AITP_JWT_SECRET must be set in .env");
    let token = crate::auth::create_token(&config, org_id, org_name, email, role)
        .expect("Token generation failed");

    let expiry = chrono::Utc::now() + chrono::Duration::hours(config.expiry_hours);

    eprintln!("\n╔══════════════════════════════════════════════════════╗");
    eprintln!("║           AITP JWT Token Generated                  ║");
    eprintln!("╚══════════════════════════════════════════════════════╝");
    eprintln!("Org ID:   {}", org_id);
    eprintln!("Org Name: {}", org_name);
    eprintln!("Email:    {}", email);
    eprintln!("Role:     {}", role);
    eprintln!("Expires:  {} UTC", expiry.format("%Y-%m-%d %H:%M:%S"));

    println!("{}", token);
    Ok(())
}
