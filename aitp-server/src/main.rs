#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use axum::{extract::Host, http::{Uri, HeaderValue, header}, response::Redirect, routing::get, Router};
use chrono::Timelike as _;
use dotenvy::dotenv;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration, Instant};
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;

mod agent;
mod ai;
mod api;
mod auth;
mod budget;
mod config;
mod crypto;
mod db;
mod enforcement;
mod error;
#[allow(dead_code)]
mod identity;
mod license;
mod metrics;
mod persistence;
mod protocol;
mod sentinel;
mod state;
mod tls;
mod trust;
mod ws;

fn main() -> anyhow::Result<()> {
    let cpu_count = num_cpus::get();

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cpu_count.min(8))
        .max_blocking_threads(4)
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    // 1. Load .env first so JWT_SECRET is available for generate-token
    dotenv().ok();

    // 2. Handle CLI subcommands BEFORE connecting to the database
    //    generate-token only needs the JWT secret from .env, no DB required.
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "generate-token" {
        let mut org_id = "test-org".to_string();
        let mut org_name = "Test Org".to_string();
        let mut email = "admin@test.com".to_string();
        let mut role = "admin".to_string();

        for i in 2..args.len() {
            match args[i].as_str() {
                "--org-id" => {
                    if i + 1 < args.len() {
                        org_id = args[i + 1].clone();
                    }
                }
                "--org-name" => {
                    if i + 1 < args.len() {
                        org_name = args[i + 1].clone();
                    }
                }
                "--email" => {
                    if i + 1 < args.len() {
                        email = args[i + 1].clone();
                    }
                }
                "--role" => {
                    if i + 1 < args.len() {
                        role = args[i + 1].clone();
                    }
                }
                _ => {}
            }
        }
        return cmd_generate_token(&org_id, &org_name, &email, &role).await;
    }

    // ── License check (first — before anything else) ──────────────────────────
    let _license = license::init_license().map_err(|e| {
        eprintln!("╔══════════════════════════════════════════════╗");
        eprintln!("║         LICENSE VALIDATION FAILED            ║");
        eprintln!("╠══════════════════════════════════════════════╣");
        eprintln!("║ {}", format!("{:width$}", e.to_string(), width = 44));
        eprintln!("║                                              ║");
        eprintln!("║ To run without a license (Community tier):   ║");
        eprintln!("║   Remove the invalid license file and retry. ║");
        eprintln!("║                                              ║");
        eprintln!("║ To renew or purchase: tanush@kernex.io       ║");
        eprintln!("╚══════════════════════════════════════════════╝");
        e
    })?;

    // Start license watchdog background task
    tokio::spawn(license::run_license_watchdog());

    // 3. Init tracing (only needed for server mode)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aitp_server=info,tower_http=warn".into()),
        )
        .init();

    // 4. Load config
    let app_config = config::AppConfig::from_env();

    // 5. Connect Database (runs migrations automatically)
    if app_config.db_path.starts_with("postgres") {
        let license = crate::license::ActiveLicense::get();
        let is_dev = std::env::var("ENVIRONMENT").unwrap_or_default() == "development";

        if !license.has_feature(&crate::license::LicenseFeature::Postgres) && !is_dev {
            eprintln!("╔══════════════════════════════════════════════╗");
            eprintln!("║       LICENSE VALIDATION RESTRICTION         ║");
            eprintln!("╠══════════════════════════════════════════════╣");
            eprintln!("║ PostgreSQL requires Startup tier or higher.  ║");
            eprintln!("║ Current tier: Community.                     ║");
            eprintln!("║ Please downgrade to SQLite or renew at       ║");
            eprintln!("║ kernex.io                                    ║");
            eprintln!("╚══════════════════════════════════════════════╝");
            std::process::exit(1);
        } else if is_dev {
            tracing::info!("PostgreSQL license restriction bypassed (DEVELOPMENT mode)");
        }
    }

    let db_pool = match db::DbPool::connect(&app_config.db_path).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!(
                "Failed to connect to database at {}: {:?}",
                app_config.db_path,
                e
            );
            std::process::exit(1);
        }
    };

    let (sentinel_tx, sentinel_rx) =
        tokio::sync::mpsc::channel::<crate::sentinel::SentinelEvent>(10_000);
    let sentinel_instance = Arc::new(crate::sentinel::SentinelState::new());

    // Pre-warm baseline memory cache globally
    let _ = sentinel_instance.load_from_db(&db_pool, "system").await;

    let gemini_client = Arc::new(crate::ai::GeminiClient::new(&app_config.gemini_api_key));

    let trust_engine = crate::trust::HybridTrustEngine::new(
        gemini_client.clone(),
        &app_config.gemini_model,
        app_config.trust_alpha,
        &app_config.trust_mode,
    );

    let memory_budget = Arc::new(budget::MemoryBudget::new());

    let enforcer = crate::enforcement::init_enforcer(&app_config.xdp_interface).await?;
    let enforcer = Arc::new(enforcer);

    // ── Server Identity ────────────────────────────────────────────────────────
    let server_identity = crate::crypto::HybridEntityIdentity::load_or_generate()
        .expect("Failed to load or generate server identity");
    let server_identity = Arc::new(server_identity);

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
        gemini_client,
    });

    // 6. Handle trigger-agent subcommand
    if args.contains(&"trigger-agent".to_string()) {
        let mut target_id = "test-entity-123".to_string();
        for i in 1..args.len() {
            if args[i] == "--entity-id" && i + 1 < args.len() {
                target_id = args[i + 1].clone();
            }
        }

        println!(
            "🚀 Triggering Agentic Threat Response for entity: {}",
            target_id
        );

        let now = chrono::Utc::now().timestamp();
        let anomaly = sentinel::Anomaly {
            entity_id: target_id.clone(),
            org_id: "system".to_string(),
            anomaly_type: sentinel::AnomalyType::LateralMovement,
            severity: sentinel::AnomalySeverity::Critical,
            description: "Manual agent trigger for investigative forensic analysis".to_string(),
            recommended_action: "Investigate and report".to_string(),
            confidence: 1.0,
            session_id: None,
            detected_at: now,
            metadata: serde_json::json!({}),
        };

        crate::agent::activate_agent(&app_state, &anomaly).await;

        println!("✅ Agent investigation complete. Results persisted to database.");
        return Ok(());
    }

    // 7. Start background tasks
    // a. Sentinel event-driven stream loop
    if app_config.sentinel_enabled {
        let s = app_state.clone();
        tokio::spawn(async move {
            sentinel::run_event_driven(s, sentinel_rx).await;
        });
    }

    // b. UDP AITP listener — the actual protocol layer
    {
        let udp_port = app_config.udp_port;
        let state_for_udp = app_state.clone();
        tokio::spawn(async move {
            if let Err(e) = start_udp_listener(udp_port, state_for_udp).await {
                tracing::error!("FATAL: UDP listener died: {}", e);
            }
        });
    }

    // c. eBPF session expiry cleanup every 60 seconds
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

    // b. Stats broadcaster — push stats to WS every 5 seconds
    //    Also updates Prometheus gauges from the same stats payload.
    {
        let s = app_state.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(5));
            let mut last_sessions: i64 = 0;
            // Track eBPF cumulative totals so we can compute per-interval deltas
            let mut last_ebpf_passed: u64 = 0;
            let mut last_ebpf_dropped: u64 = 0;
            let mut last_ebpf_bypassed: u64 = 0;
            loop {
                tick.tick().await;
                let uptime = s.start_time.elapsed().as_secs();

                // Update WS subscriber gauge
                metrics::WS_SUBSCRIBERS.set(s.hub.total_subscribers() as f64);

                // ── eBPF stats ──────────────────────────────────────────────
                if let Ok(ebpf_stats) = s.enforcer.stats().await {
                    // Delta-increment the counters (they're cumulative in BPF maps)
                    let pass_delta = ebpf_stats.packets_passed.saturating_sub(last_ebpf_passed);
                    let drop_delta = ebpf_stats.packets_dropped.saturating_sub(last_ebpf_dropped);
                    let bypass_delta = ebpf_stats
                        .packets_bypassed
                        .saturating_sub(last_ebpf_bypassed);

                    if pass_delta > 0 {
                        metrics::EBPF_PACKETS
                            .with_label_values(&["pass"])
                            .inc_by(pass_delta as f64);
                    }
                    if drop_delta > 0 {
                        metrics::EBPF_PACKETS
                            .with_label_values(&["drop"])
                            .inc_by(drop_delta as f64);
                    }
                    if bypass_delta > 0 {
                        metrics::EBPF_PACKETS
                            .with_label_values(&["bypass"])
                            .inc_by(bypass_delta as f64);
                    }
                    metrics::EBPF_PERMITS.set(ebpf_stats.active_permits as f64);

                    last_ebpf_passed = ebpf_stats.packets_passed;
                    last_ebpf_dropped = ebpf_stats.packets_dropped;
                    last_ebpf_bypassed = ebpf_stats.packets_bypassed;
                }

                if let Ok(stats) = s.db.get_stats(uptime).await {
                    // Update Prometheus gauges
                    metrics::ACTIVE_SESSIONS.set(stats.active_sessions as f64);
                    let delta = stats.active_sessions.saturating_sub(last_sessions) as f64;
                    metrics::SESSION_RATE.set(delta / 5.0);
                    last_sessions = stats.active_sessions;

                    // Broadcast stats to all connected org channels
                    let stats_event = db::models::WsEvent::Stats {
                        active_sessions: stats.active_sessions,
                        blocked_today: stats.blocked_today,
                        ai_calls: stats.ai_calls,
                        avg_trust: stats.avg_trust,
                        entities_online: stats.entities_online,
                        threats_detected_today: stats.threats_detected_today,
                        uptime_secs: stats.uptime_secs,
                    };
                    // log() broadcasts to all active org channels
                    // For stats we broadcast to every org since it's aggregate data
                    s.hub.log("STATS", &serde_json::to_string(&stats_event).unwrap_or_default());
                }
            }
        });
    }

    // c. Session cleanup — expire old sessions every 60 seconds
    {
        let s = app_state.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                if let Ok(expired) = s.db.expire_old_sessions(3600).await {
                    if expired > 0 {
                        s.hub
                            .log("INFO", &format!("{} stale sessions expired", expired));
                    }
                }
            }
        });
    }

    // d. WS hub empty-channel cleanup every 5 minutes
    {
        let hub = app_state.hub.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(300));
            loop {
                tick.tick().await;
                hub.cleanup_empty_channels();
            }
        });
    }

    // 8. Build Axum router with security headers (FIX 4)
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .merge(api::router())
        .route("/ws", get(ws::ws_handler))
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(app_state.clone())
        .fallback_service(
            tower_http::services::ServeDir::new("static")
                .fallback(tower_http::services::ServeFile::new("static/index.html")),
        )
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'; connect-src 'self' wss:"),
        ));

    // 9. Print startup banner
    print_banner(&app_config, &server_identity);

    // 10. Start server — auto-select HTTP or HTTPS
    match tls::detect_mode(&app_config) {
        tls::ServerMode::Http { port } => {
            let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
            tracing::info!("Listening on http://{}", addr);
            axum_server::bind(addr)
                .serve(app.into_make_service())
                .await?;
        }
        tls::ServerMode::Https {
            http_port,
            https_port,
            cert,
            key,
        } => {
            let rustls_config = tls::load_rustls_config(&cert, &key).await?;
            let https_addr: SocketAddr = format!("0.0.0.0:{}", https_port).parse()?;

            // Spawn HTTP→HTTPS redirect on port 80
            let redirect_app = Router::new().fallback(|Host(host): Host, uri: Uri| async move {
                let target = format!("https://{}{}", host, uri);
                Redirect::permanent(&target)
            });

            tokio::spawn(async move {
                let http_addr: SocketAddr = format!("0.0.0.0:{}", http_port)
                    .parse()
                    .expect("Invalid HTTP redirect address");
                tracing::info!("HTTP→HTTPS redirect listening on http://{}", http_addr);
                axum_server::bind(http_addr)
                    .serve(redirect_app.into_make_service())
                    .await
                    .expect("HTTP redirect server failed");
            });

            tracing::info!("Listening on https://{}", https_addr);
            axum_server::bind_rustls(https_addr, rustls_config)
                .serve(app.into_make_service())
                .await?;
        }
    }

    Ok(())
}

// ── FIX 1: UDP AITP Listener ──────────────────────────────────────────────────

async fn start_udp_listener(
    port: u16,
    state: Arc<state::AppState>,
) -> anyhow::Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(format!("0.0.0.0:{}", port)).await?
    );
    tracing::info!("AITP UDP listener active on 0.0.0.0:{}", port);

    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer_addr) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("UDP recv_from error: {}", e);
                continue;
            }
        };

        crate::metrics::UDP_PACKETS_RECEIVED.inc();

        let packet_data = buf[..len].to_vec();
        let sock = Arc::clone(&socket);
        let st = state.clone();

        tokio::spawn(async move {
            if let Err(e) = process_aitp_packet(packet_data, peer_addr, sock, st).await {
                tracing::warn!("[UDP] Packet error from {}: {}", peer_addr, e);
                crate::metrics::UDP_HANDSHAKES_COMPLETED
                    .with_label_values(&["failed"])
                    .inc();
            }
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

    // Route on flags
    if header.is_syn() {
        // Phase 1 — new handshake initiated
        let session_id = header.session_id;
        let intent_code = crate::protocol::IntentCode::from_u16(header.intent);
        let source_entity_id = hex::encode(header.source_id());

        tracing::info!(
            "[UDP] Phase 1 SYN from {} — session={} intent={}",
            peer_addr, session_id, intent_code
        );

        // Build SYN-ACK response with server's public key material
        let syn_ack = AitpHeaderV4 {
            version: 4,
            flags: FLAG_SYN | FLAG_ACK,
            intent: header.intent,
            session_id,
            timestamp: chrono::Utc::now().timestamp_micros() as u64,
            nonce: rand::random::<[u8; 12]>(),
            algorithm: 2, // HybridPQ
            source_pk: state.server_identity.public_key_bytes().to_vec(),
            dest_id: header.source_id(),
            signature: vec![],
            payload_len: 0,
        };

        socket.send_to(&syn_ack.to_bytes(), peer_addr).await?;

        // For sessions with valid intent (not Unknown), evaluate trust and register with eBPF
        if intent_code != crate::protocol::IntentCode::Unknown {
            // Build minimal context from handshake data
            let ctx = SessionContext {
                source_entity_id: source_entity_id.clone(),
                org_id: "system".to_string(), // resolved via entity lookup in production
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
            let trust_score = result.trust_score;
            let verdict_str = result.verdict.as_str();

            tracing::info!(
                "[UDP] Trust eval for session={}: score={} verdict={}",
                session_id, trust_score, verdict_str
            );

            // Register in eBPF kernel maps
            let source_id_bytes: [u8; 32] = {
                let decoded = hex::decode(&source_entity_id).unwrap_or_else(|_| vec![0; 32]);
                let mut arr = [0u8; 32];
                let len = decoded.len().min(32);
                arr[..len].copy_from_slice(&decoded[..len]);
                arr
            };
            let dest_id_bytes: [u8; 32] = header.dest_id;
            let verdict_byte = match result.verdict {
                crate::trust::TrustVerdict::Allow => 1u8,
                crate::trust::TrustVerdict::Monitor => 2u8,
                crate::trust::TrustVerdict::Deny => 0u8,
            };

            crate::enforcement::register_kernel_session(
                &state.enforcer,
                session_id,
                &source_id_bytes,
                &dest_id_bytes,
                header.intent,
                trust_score,
                verdict_byte,
                [0u8; crate::crypto::MLKEM768_SS_BYTES],
            ).await;

            crate::metrics::UDP_HANDSHAKES_COMPLETED
                .with_label_values(&["completed"])
                .inc();

            // Send sentinel event
            state.send_sentinel_event(crate::sentinel::SentinelEvent {
                entity_id: source_entity_id,
                org_id: "system".to_string(),
                session_id: session_id.to_string(),
                dest_entity_id: hex::encode(header.dest_id),
                intent: intent_code.as_str().to_string(),
                trust_score,
                verdict: verdict_str.to_string(),
                bytes_tx: bytes.len() as u64,
                occurred_at: chrono::Utc::now().timestamp(),
                signal: crate::sentinel::SentinelEvent::classify(
                    intent_code.as_str(),
                    trust_score,
                    128.0,
                    false,
                    verdict_str,
                ),
            });
        }

    } else if header.has_flag(FLAG_FIN) {
        tracing::info!("[UDP] FIN received for session={} from {}", header.session_id, peer_addr);
        // Revoke eBPF permit on session teardown
        let prefix: [u8; 8] = header.dest_id[..8].try_into().unwrap_or([0u8; 8]);
        let _ = state.enforcer.revoke_entity(&prefix).await;
    } else {
        tracing::debug!("[UDP] Data packet session={} len={}", header.session_id, bytes.len());
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

    // Metadata to stderr
    eprintln!("\n╔══════════════════════════════════════════════════════╗");
    eprintln!("║           AITP JWT Token Generated                  ║");
    eprintln!("╚══════════════════════════════════════════════════════╝");
    eprintln!("Org ID:   {}", org_id);
    eprintln!("Org Name: {}", org_name);
    eprintln!("Email:    {}", email);
    eprintln!("Role:     {}", role);
    eprintln!("Expires:  {} UTC", expiry.format("%Y-%m-%d %H:%M:%S"));

    eprintln!("\n-- Token (printed to stdout) --");
    // Raw token to stdout
    println!("{}", token);

    eprintln!("\n-- Shell Variable --");
    eprintln!("TOKEN=\"{}\"", token);
    eprintln!("\n-- REST Test --");
    eprintln!("curl -s http://localhost:3000/api/auth/me -H \"Authorization: Bearer $TOKEN\" | jq");
    eprintln!("\n-- WebSocket Test --");
    eprintln!("websocat \"ws://localhost:3000/ws?token=$TOKEN\"");
    eprintln!();

    use std::io::Write;
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

    Ok(())
}

fn print_banner(config: &config::AppConfig, identity: &crate::crypto::HybridEntityIdentity) {
    let (mode_line, api_line, dashboard_line) = if config.tls_enabled() {
        (
            "║  Mode:      HTTPS PRODUCTION                    ║".to_string(),
            format!(
                "║  API:       https://0.0.0.0:{:<5}             ║",
                config.https_port
            ),
            format!(
                "║  Dashboard: https://localhost:{:<5}           ║",
                config.https_port
            ),
        )
    } else {
        (
            "║  Mode:      HTTP DEV (set TLS_* vars for prod)  ║".to_string(),
            format!(
                "║  API:       http://0.0.0.0:{:<5}                ║",
                config.http_port
            ),
            format!(
                "║  Dashboard: http://localhost:{:<5}              ║",
                config.http_port
            ),
        )
    };

    println!();
    println!("    ╔═══════════════════════════════════════════════════╗");
    println!("    ║         Kelan Intelligence Core v0.3             ║");
    println!("    ╠═══════════════════════════════════════════════════╣");
    println!("    {}", mode_line);
    println!("    {}", api_line);
    println!("    {}", dashboard_line);
    println!(
        "    ║  AITP/UDP:  0.0.0.0:{:<5}                        ║",
        config.udp_port
    );
    println!("    ║  Sentinel:  ACTIVE                                ║");
    println!("    ╚═══════════════════════════════════════════════════╝");
    println!();
    println!("    EntityID: {}", identity.entity_id_hex());
    println!("    Version:  0.3.0");
    println!("    Config:   {}", config.summary());
    println!("    Status:   ONLINE");
    println!(
        "    Crypto:   {} (Strict: {:?})",
        if config.advertise_pq {
            "Hybrid Post-Quantum (ML-DSA-65) ✅"
        } else {
            "Classical (Ed25519) ⚠️"
        },
        config.min_crypto_algorithm
    );
    println!();
}
