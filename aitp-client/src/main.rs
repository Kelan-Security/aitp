// AITP Client Agent — main.rs
// CLI entry point for all aitp-client commands.

mod config;
mod daemon;
mod handshake;
mod identity;
mod install;
mod interceptor;
mod ipc;
mod session;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;

#[derive(Parser)]
#[command(
    name = "aitp-client",
    version = "0.3.0",
    about = "AITP Client Agent — Identity-First Connection Guard",
    long_about = "Lightweight daemon that enforces AITP protocol on every device.\nRuns the 5-phase handshake for all outgoing connections and evaluates trust via the Intelligence Core."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the AITP client daemon in the foreground
    Start,
    /// Start as a background daemon (detaches from terminal)
    Daemon,
    /// Stop the running daemon
    Stop,
    /// Show daemon status: entity ID, connection, active sessions
    Status,
    /// Enroll this device with the Intelligence Core
    Enroll {
        /// Organisation email (overrides AITP_EMAIL env var)
        #[arg(long)]
        email: Option<String>,
        /// Organisation password (overrides AITP_PASSWORD env var)
        #[arg(long)]
        password: Option<String>,
    },
    /// Run a single test handshake and display trust evaluation result
    TestConnection {
        /// Destination entity ID hex (defaults to self)
        #[arg(long)]
        dest: Option<String>,
        /// Intent to declare
        #[arg(long, default_value = "ModelInference")]
        intent: String,
    },
    /// Install as a system service (systemd/launchd/Windows Service)
    Install,
    /// Remove the system service
    Uninstall,
    /// Print current configuration
    Config,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env if present (dev convenience)
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();
    let config = config::ClientConfig::load()?;

    // Set up tracing
    let log_level =
        std::env::var("AITP_LOG_LEVEL").unwrap_or_else(|_| config.logging.level.clone());

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log_level)),
        )
        .init();

    match cli.command {
        Command::Start => {
            print_banner();
            let identity = identity::EntityIdentity::generate_or_load(&config)?;
            daemon::run_daemon(config, identity).await?;
        }

        Command::Daemon => {
            println!("{} Starting AITP Client in background…", "→".blue());
            // On Unix, fork and detach.
            // Simple approach: re-exec with nohup
            let exe = std::env::current_exe()?;
            let child = std::process::Command::new(&exe)
                .arg("start")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            println!(
                "{} AITP Client daemon started (PID {})",
                "✓".green(),
                child.id()
            );
            std::mem::forget(child); // detach
        }

        Command::Stop => {
            println!("{} Stopping AITP Client daemon…", "→".blue());
            let pid_file = "/tmp/aitp-client.pid";
            if std::path::Path::new(pid_file).exists() {
                let pid: u32 = std::fs::read_to_string(pid_file)?.trim().parse()?;
                #[cfg(unix)]
                {
                    let _ = std::process::Command::new("kill")
                        .arg(pid.to_string())
                        .status();
                }
                std::fs::remove_file(pid_file)?;
                println!("{} Daemon stopped (PID {})", "✓".green(), pid);
            } else {
                println!("{} No PID file — daemon may not be running", "!".yellow());
            }
        }

        Command::Status => match ipc::query_status().await {
            Ok(status) => {
                println!();
                println!("{}", "AITP Client Status".bold());
                println!("{}", "─".repeat(40));
                println!("  Entity ID    : {}", status.entity_id.cyan());
                println!(
                    "  Server       : {} {}",
                    status.server_address,
                    if status.server_connected {
                        "● CONNECTED".green().to_string()
                    } else {
                        "○ DISCONNECTED".red().to_string()
                    }
                );
                println!("  Sessions     : {}", status.active_sessions);
                println!("  Uptime       : {}s", status.uptime_secs);
                println!("  Interception : {}", status.interception_mode);

                if !status.sessions.is_empty() {
                    println!();
                    println!("{}", "Active Sessions:".bold());
                    for s in &status.sessions {
                        let verdict_colored = match s.verdict.as_str() {
                            "Allow" => s.verdict.green().to_string(),
                            "Deny" => s.verdict.red().to_string(),
                            _ => s.verdict.yellow().to_string(),
                        };
                        println!(
                            "  {} {}  trust:{} age:{}s  [{}]",
                            verdict_colored, s.session_id, s.trust_score, s.age_secs, s.intent
                        );
                    }
                }
                println!();
            }
            Err(e) => {
                println!("{} Daemon not running: {}", "✗".red(), e);
            }
        },

        Command::Enroll { email, password } => {
            if let Some(e) = email {
                std::env::set_var("AITP_EMAIL", e);
            }
            if let Some(p) = password {
                std::env::set_var("AITP_PASSWORD", p);
            }

            println!("{} Enrolling device with Intelligence Core…", "→".blue());
            let identity = identity::EntityIdentity::generate_or_load(&config)?;
            daemon::enroll_device(&config, &identity).await?;
        }

        Command::TestConnection { dest, intent } => {
            let config_clone = config.clone();
            let identity = identity::EntityIdentity::generate_or_load(&config_clone)?;

            let parse_intent = |s: &str| match s.to_lowercase().as_str() {
                "modelinference" | "inference" => handshake::Intent::ModelInference,
                "agentcoordinate" | "agent" => handshake::Intent::AgentCoordinate,
                "datasync" | "sync" => handshake::Intent::DataSync,
                "controlsignal" | "control" => handshake::Intent::ControlSignal,
                "filetransfer" | "file" => handshake::Intent::FileTransfer,
                "apicall" | "api" => handshake::Intent::ApiCall,
                _ => handshake::Intent::ModelInference,
            };

            let intent_code = parse_intent(&intent);
            let dest_id = dest.unwrap_or_else(|| {
                daemon::load_server_entity_id().unwrap_or_else(|| identity.entity_id_full_hex())
            });

            let identity_arc =
                std::sync::Arc::new(identity::EntityIdentity::generate_or_load(&config_clone)?);
            let config_arc = std::sync::Arc::new(config_clone.clone());

            let handshake = handshake::AitpHandshake::new(identity_arc.clone(), config_arc);

            println!("\n{} Running 5-phase AITP handshake…\n", "→".blue());
            println!("  Entity ID : {}", identity_arc.entity_id_hex().cyan());
            println!("  Server    : {}", config_clone.api_base_url());
            println!("  Intent    : {}", intent_code);
            println!("  Dest      : {}", &dest_id[..dest_id.len().min(16)]);
            println!();

            let t0 = std::time::Instant::now();
            match handshake.establish(&dest_id, intent_code).await {
                Ok(permit) => {
                    let latency = t0.elapsed();
                    println!("{}", "━".repeat(48));
                    println!("  Phase 1  : {} HELLO", "✓".green());
                    println!(
                        "  Phase 2  : {} IDENTITY_EXCHANGE + nonce signed",
                        "✓".green()
                    );
                    println!(
                        "  Phase 3  : {} INTENT_DECLARE ({})",
                        "✓".green(),
                        intent_code
                    );
                    println!(
                        "  Phase 4  : {} Trust evaluation ({})",
                        "✓".green(),
                        permit.eval_source
                    );
                    println!("  Phase 5  : {} SESSION_GRANT", "✓".green());
                    println!("{}", "━".repeat(48));
                    println!(
                        "  Session  : {}",
                        &permit.session_id[..permit.session_id.len().min(12)]
                    );
                    println!("  Trust    : {}", permit.trust_score);
                    println!(
                        "  Verdict  : {}",
                        match permit.verdict {
                            handshake::Verdict::Allow => "ALLOW".green().to_string(),
                            handshake::Verdict::Deny => "DENY".red().to_string(),
                            handshake::Verdict::Monitor => "MONITOR".yellow().to_string(),
                        }
                    );
                    println!("  Reason   : {}", permit.reasoning.dimmed());
                    println!("  Latency  : {}ms", latency.as_millis());
                    println!();

                    if permit.is_allowed() {
                        println!("{} Connection would be ALLOWED", "✓".green());
                    } else {
                        println!("{} Connection would be DENIED (ECONNREFUSED)", "✗".red());
                    }
                }
                Err(e) => {
                    let latency = t0.elapsed();
                    println!("{}", "━".repeat(48));
                    println!(
                        "{} Handshake FAILED after {}ms",
                        "✗".red(),
                        latency.as_millis()
                    );
                    println!("  Error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Command::Install => {
            println!("{} Installing AITP Client as system service…", "→".blue());
            install::install_service()?;
        }

        Command::Uninstall => {
            println!("{} Removing AITP Client system service…", "→".blue());
            install::uninstall_service()?;
        }

        Command::Config => {
            println!("{}", "AITP Client Configuration".bold());
            println!("{}", "─".repeat(40));
            println!(
                "  Config file : {:?}",
                config::ClientConfig::default_config_path()
            );
            println!("  Server      : {}", config.api_base_url());
            println!("  Entity type : {}", config.agent.entity_type);
            println!(
                "  Department  : {}",
                if config.agent.department.is_empty() {
                    "—"
                } else {
                    &config.agent.department
                }
            );
            println!("  Clearance   : {}", config.agent.clearance_level);
            println!("  Interception: {}", config.interception.mode);
            println!(
                "  Excl ports  : {}",
                config
                    .interception
                    .exclude_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("  Log level   : {}", config.logging.level);
        }
    }

    Ok(())
}

fn print_banner() {
    println!();
    println!("{}", "AITP Client Agent v0.3.0".bold().cyan());
    println!("{}", "Identity-First · Intent-Bound · Zero-Trust".dimmed());
    println!();
}
