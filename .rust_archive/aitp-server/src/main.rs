use aitp_server::{config, license, run_server, cmd_generate_token};
use dotenvy::dotenv;

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
    dotenv().ok();

    let args: Vec<String> = std::env::args().collect();

    // ── kelan doctor: pre-flight diagnostics ──────────────────────────────
    if args.iter().any(|a| a == "--doctor" || a == "doctor") {
        // Re-exec as kelan-doctor binary (same directory as this binary)
        let bin_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("kelan-doctor")));

        if let Some(doctor_path) = bin_path {
            if doctor_path.exists() {
                let status = std::process::Command::new(&doctor_path)
                    .envs(std::env::vars())
                    .status()
                    .unwrap_or_else(|e| {
                        eprintln!("Failed to run kelan-doctor: {}", e);
                        std::process::exit(1);
                    });
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        // Fallback: inline minimal doctor if binary not found
        eprintln!("kelan-doctor binary not found in PATH. Build with: cargo build -p aitp-server --bin kelan-doctor");
        std::process::exit(1);
    }

    if args.len() > 1 && args[1] == "generate-token" {
        let mut org_id = "test-org".to_string();
        let mut org_name = "Test Org".to_string();
        let mut email = "admin@test.com".to_string();
        let mut role = "admin".to_string();

        for i in 2..args.len() {
            match args[i].as_str() {
                "--org-id"   => if i + 1 < args.len() { org_id   = args[i + 1].clone(); }
                "--org-name" => if i + 1 < args.len() { org_name = args[i + 1].clone(); }
                "--email"    => if i + 1 < args.len() { email    = args[i + 1].clone(); }
                "--role"     => if i + 1 < args.len() { role     = args[i + 1].clone(); }
                _ => {}
            }
        }
        return cmd_generate_token(&org_id, &org_name, &email, &role).await;
    }

    let _license = license::init_license()?;
    tokio::spawn(license::run_license_watchdog());

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aitp_server=info,tower_http=warn".into()),
        )
        .init();

    let app_config = config::AppConfig::from_env();
    
    run_server(app_config).await
}
