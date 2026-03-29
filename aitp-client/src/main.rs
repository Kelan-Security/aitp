// Kelan Security Client Agent — main.rs
// CLI entry point for kelan-agent.

mod channel;
mod config;
mod daemon;
mod enroll;
mod handshake;
mod heartbeat;
mod identity;
mod install;
mod interceptor;
mod ipc;
mod metrics;
mod session;

use clap::{Parser, Subcommand};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "kelan-agent")]
#[command(version = "0.3.0")]
#[command(about = "Kelan Security Client Agent — transport-layer security daemon")]
#[command(
    long_about = "Lightweight daemon that installs on every device in an organisation.\nTransparently intercepts outgoing connections and routes them through\nthe Kelan Intelligence Core for identity verification and AI trust evaluation."
)]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "/etc/kelan/kelan-agent.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the agent daemon in the foreground
    Start,
    /// Start the agent daemon in the background
    Daemon,
    /// Stop the running daemon
    Stop,
    /// Show current agent status
    Status,
    /// Enroll this device with the Kelan Intelligence Core
    Enroll {
        /// Intelligence Core address
        #[arg(short, long)]
        server: String,
        /// Authentication token from the Intelligence Core admin
        #[arg(short, long)]
        token: String,
    },
    /// Test connection to Intelligence Core and show trust evaluation
    Test {
        /// Target to test (host:port)
        #[arg(default_value = "kelan-test.internal:443")]
        target: String,
    },
    /// Install as system service (systemd/launchd)
    Install,
    /// Remove system service
    Uninstall,
    /// Show agent configuration
    Config,
    /// Generate a new keypair (replaces existing — use with caution)
    ResetKeys,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_path = std::path::PathBuf::from(&cli.config);
    let config = config::AgentConfig::load(&config_path).unwrap_or_default();

    // Init tracing
    init_logging(&config);

    match cli.command {
        Commands::Start => {
            print_banner();
            daemon::run(Arc::new(config), config_path).await?;
        }

        Commands::Daemon => {
            // Fork: re-exec in background
            let exe = std::env::current_exe()?;
            let child = std::process::Command::new(&exe)
                .arg("--config")
                .arg(&cli.config)
                .arg("start")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            println!("Kelan Security Agent daemon started (PID {})", child.id());
            // Write PID file
            let _ = std::fs::write("/tmp/kelan-agent.pid", child.id().to_string());
            std::mem::forget(child); // detach
        }

        Commands::Stop => {
            let pid_str = std::fs::read_to_string("/tmp/kelan-agent.pid")
                .map_err(|_| anyhow::anyhow!("Agent not running (no PID file)"))?;
            let pid: i32 = pid_str.trim().parse()?;
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            )?;
            let _ = std::fs::remove_file("/tmp/kelan-agent.pid");
            println!("Agent stopped (PID {})", pid);
        }

        Commands::Status => {
            let identity = identity::load_or_generate()?;
            identity::print_identity_summary(&identity);

            match ipc::query_status().await {
                Ok(status) => {
                    println!("{}", serde_json::to_string_pretty(&status)?);
                }
                Err(e) => {
                    eprintln!("Agent not running: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Enroll { server, token } => {
            enroll::run(server, token, &config_path).await?;
        }

        Commands::Test { target } => {
            run_test(&config, &target, config_path.parent()).await?;
        }

        Commands::Install => {
            install::install_service()?;
        }

        Commands::Uninstall => {
            install::uninstall_service()?;
        }

        Commands::Config => {
            println!("{}", toml::to_string_pretty(&config)?);
        }

        Commands::ResetKeys => {
            print!("WARNING: This will replace your keypair. Type 'yes' to confirm: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            if line.trim() == "yes" {
                let entry = keyring::Entry::new("kelan-agent", "hybrid-pq-private-key-v2")?;
                entry.delete_password().ok();
                let entry_v1 = keyring::Entry::new("kelan-agent", "ed25519-private-key")?;
                entry_v1.delete_password().ok();
                println!("Keys reset (both v1 Ed25519 and v2 Hybrid PQ). Run 'kelan-agent enroll' to re-enroll.");
            } else {
                println!("Aborted.");
            }
        }
    }

    Ok(())
}

fn init_logging(config: &config::AgentConfig) {
    let level = std::env::var("KELAN_LOG_LEVEL").unwrap_or_else(|_| config.logging.level.clone());

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&level)),
        )
        .init();
}

fn print_banner() {
    eprintln!();
    eprintln!("┌─────────────────────────────────────────────┐");
    eprintln!("│  Kelan Security Client Agent v0.3.0                 │");
    eprintln!("│  Transport-Layer Security Daemon            │");
    eprintln!("│  Identity-First · Intent-Bound · Zero-Trust │");
    eprintln!("└─────────────────────────────────────────────┘");
    eprintln!();
}

async fn run_test(
    config: &config::AgentConfig,
    target: &str,
    _key_dir: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let identity = Arc::new(identity::load_or_generate()?);

    // Parse target
    let (host, port) = if let Some(idx) = target.rfind(':') {
        let h = &target[..idx];
        let p: u16 = target[idx + 1..]
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid port in target: {}", target))?;
        (h.to_string(), p)
    } else {
        (target.to_string(), 443)
    };

    let intent = handshake::infer_intent(&host, port);

    println!();
    println!("Evaluating: {}:{} ({})", host, port, intent);

    let t0 = std::time::Instant::now();
    let hs =
        handshake::AitpHandshake::new(identity, &config.server.address, config.server.udp_port)
            .await?;

    let dest_id = "0".repeat(64);
    match hs.establish(&dest_id, intent).await {
        Ok(permit) => {
            let latency = t0.elapsed();
            println!("Trust score: {}/255", permit.trust_score);
            println!("Verdict: {}", permit.verdict);
            if !permit.ai_reasoning.is_empty() {
                println!("AI reasoning: \"{}\"", permit.ai_reasoning);
            }
            println!("Latency: {:.1}ms", latency.as_secs_f64() * 1000.0);
        }
        Err(e) => {
            let latency = t0.elapsed();
            println!("DENIED after {:.1}ms", latency.as_secs_f64() * 1000.0);
            println!("Error: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
