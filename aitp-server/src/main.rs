#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use axum::{extract::Host, http::Uri, response::Redirect, routing::get, Router};
use dotenvy::dotenv;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{interval, Duration, Instant};
use tower_http::cors::{Any, CorsLayer};

mod agent;
mod api;
mod auth;
mod budget;
mod config;
mod crypto;
mod db;
#[allow(dead_code)]
mod enforcement;
mod error;
#[allow(dead_code)]
mod identity;
#[allow(dead_code)]
mod protocol;
mod sentinel;
mod state;
mod tls;
#[allow(dead_code)]
mod trust;
mod ws;
mod license;
mod metrics;

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
    let _license = license::init_license()
        .map_err(|e| {
            eprintln!("╔══════════════════════════════════════════════╗");
            eprintln!("║         LICENSE VALIDATION FAILED            ║");
            eprintln!("╠══════════════════════════════════════════════╣");
            eprintln!("║ {}",
                format!("{:width$}", e.to_string(), width = 44));
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
        if !license.has_feature(&crate::license::LicenseFeature::Postgres) {
            eprintln!("╔══════════════════════════════════════════════╗");
            eprintln!("║       LICENSE VALIDATION RESTRICTION         ║");
            eprintln!("╠══════════════════════════════════════════════╣");
            eprintln!("║ PostgreSQL requires Startup tier or higher.  ║");
            eprintln!("║ Current tier: Community.                     ║");
            eprintln!("║ Please downgrade to SQLite or renew at       ║");
            eprintln!("║ kernex.io                                    ║");
            eprintln!("╚══════════════════════════════════════════════╝");
            std::process::exit(1);
        }
    }
    
    let db_pool = match db::DbPool::connect(&app_config.db_path).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!("Failed to connect to database at {}: {:?}", app_config.db_path, e);
            std::process::exit(1);
        }
    };

    let (sentinel_tx, sentinel_rx) = tokio::sync::mpsc::channel::<crate::sentinel::SentinelEvent>(10_000);
    let sentinel_instance = Arc::new(crate::sentinel::SentinelState::new());

    // Pre-warm baseline memory cache globally
    let _ = sentinel_instance.load_from_db(&db_pool, "system").await;

    let trust_engine = crate::trust::HybridTrustEngine::new(
        &app_config.gemini_api_key,
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
                metrics::WS_SUBSCRIBERS.set(s.hub.tx.receiver_count() as f64);

                // ── eBPF stats ──────────────────────────────────────────────
                if let Ok(ebpf_stats) = s.enforcer.stats().await {
                    // Delta-increment the counters (they're cumulative in BPF maps)
                    let pass_delta = ebpf_stats.packets_passed.saturating_sub(last_ebpf_passed);
                    let drop_delta = ebpf_stats.packets_dropped.saturating_sub(last_ebpf_dropped);
                    let bypass_delta = ebpf_stats.packets_bypassed.saturating_sub(last_ebpf_bypassed);

                    if pass_delta > 0 {
                        metrics::EBPF_PACKETS.with_label_values(&["pass"]).inc_by(pass_delta as f64);
                    }
                    if drop_delta > 0 {
                        metrics::EBPF_PACKETS.with_label_values(&["drop"]).inc_by(drop_delta as f64);
                    }
                    if bypass_delta > 0 {
                        metrics::EBPF_PACKETS.with_label_values(&["bypass"]).inc_by(bypass_delta as f64);
                    }
                    metrics::EBPF_PERMITS.set(ebpf_stats.active_permits as f64);

                    last_ebpf_passed   = ebpf_stats.packets_passed;
                    last_ebpf_dropped  = ebpf_stats.packets_dropped;
                    last_ebpf_bypassed = ebpf_stats.packets_bypassed;
                }

                if let Ok(stats) = s.db.get_stats(uptime).await {
                    // Update Prometheus gauges
                    metrics::ACTIVE_SESSIONS.set(stats.active_sessions as f64);
                    let delta = stats.active_sessions.saturating_sub(last_sessions) as f64;
                    metrics::SESSION_RATE.set(delta / 5.0);
                    last_sessions = stats.active_sessions;

                    s.hub.broadcast(db::models::WsEvent::Stats {
                        active_sessions: stats.active_sessions,
                        blocked_today: stats.blocked_today,
                        ai_calls: stats.ai_calls,
                        avg_trust: stats.avg_trust,
                        entities_online: stats.entities_online,
                        threats_detected_today: stats.threats_detected_today,
                        uptime_secs: stats.uptime_secs,
                    });
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

    // 8. Build Axum router
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .merge(api::router())
        .route("/ws", get(ws::ws_handler))
        // Prometheus metrics endpoint — no auth, dedicated route outside API router
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(app_state.clone())
        .fallback_service(
            tower_http::services::ServeDir::new("static")
                .fallback(tower_http::services::ServeFile::new("static/index.html")),
        )
        .layer(cors);

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
            let redirect_app = Router::new().fallback(
                |Host(host): Host, uri: Uri| async move {
                    let target = format!("https://{}{}", host, uri);
                    Redirect::permanent(&target)
                },
            );

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
    println!("    Crypto:   {} (Strict: {:?})", 
        if config.advertise_pq { "Hybrid Post-Quantum (ML-DSA-65) ✅" } else { "Classical (Ed25519) ⚠️" },
        config.min_crypto_algorithm
    );
    println!();
}
