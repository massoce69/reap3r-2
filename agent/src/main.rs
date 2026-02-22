// ─────────────────────────────────────────────────────────────
// MassVision Agent v2 – Entry-point
// ─────────────────────────────────────────────────────────────
use clap::{Parser, Subcommand};
use tracing::info;
use anyhow::Result;

mod agent;
mod storage;
mod network;
mod protocol;
mod modules;
mod update;
mod policy;
mod security;
mod platform;

// ── CLI ──────────────────────────────────────────────────────
#[derive(Parser)]
#[command(name = "massvision-agent", version, about = "MassVision Enterprise Agent")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install as system service (Windows/Linux/macOS)
    Install,
    /// Uninstall system service
    Uninstall,
    /// Run in foreground (debug / troubleshooting)
    Run,
    /// Print local agent status
    Status,
    /// Enroll this machine with MassVision server
    Enroll {
        #[arg(short, long)]
        token: String,
        #[arg(short, long)]
        server: String,
    },
}

// ── main ─────────────────────────────────────────────────────
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Install)   => platform::install_service()?,
        Some(Commands::Uninstall) => platform::uninstall_service()?,
        Some(Commands::Run)       => run_foreground()?,
        Some(Commands::Status)    => show_status()?,
        Some(Commands::Enroll { token, server }) => {
            run_enrollment(token, server)?;
        }
        None => {
            // Default behaviour: run as OS service
            #[cfg(windows)]
            {
                // If not started by the Windows Service Control Manager (e.g. launched from a
                // scheduled task / interactive session), the service dispatcher will fail.
                // Fall back to foreground mode so deployments remain functional.
                if let Err(e) = platform::run_windows_service() {
                    eprintln!("Service dispatcher not available, falling back to foreground mode: {e}");
                    run_foreground()?;
                }
            }
            #[cfg(not(windows))]
            {
                run_foreground()?;
            }
        }
    }
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────
fn run_foreground() -> Result<()> {
    // Used by the server to route UI features (e.g. Remote Desktop) to an interactive session.
    // A foreground process started from a Scheduled Task is typically interactive.
    std::env::set_var("MASSVISION_RUN_MODE", "interactive");
    let _guard = init_logging();
    info!("MassVision Agent v{} – foreground mode", env!("CARGO_PKG_VERSION"));
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut core = agent::AgentCore::new().await?;
        core.run().await
    })
}

/// Called from Windows service dispatcher (platform module).
pub fn run_agent_service() -> Result<()> {
    std::env::set_var("MASSVISION_RUN_MODE", "service");
    let _guard = init_logging();
    info!("MassVision Agent v{} – service mode", env!("CARGO_PKG_VERSION"));
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut core = agent::AgentCore::new().await?;
        core.run().await
    })
}

fn run_enrollment(token: String, server: String) -> Result<()> {
    let _guard = init_logging();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(security::enroll(&token, &server))
}

fn show_status() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let cfg = agent::AgentConfig::load()?;
        let db  = storage::Database::open(&cfg)?;
        println!("MassVision Agent v{}", env!("CARGO_PKG_VERSION"));
        println!("Machine ID      : {}", cfg.agent.machine_id);
        println!("Server          : {}", cfg.server.url);
        println!("Pending jobs    : {}", db.count_pending_jobs()?);
        println!("Unsent heartbeats: {}", db.count_unsent_heartbeats()?);
        Ok(())
    })
}

fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    let log_dir = platform::get_log_dir();
    std::fs::create_dir_all(&log_dir).ok();
    let file_appender = tracing_appender::rolling::daily(&log_dir, "massvision-agent.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(non_blocking)
        .json()
        .init();
    guard
}
