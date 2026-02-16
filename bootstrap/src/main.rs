// ──────────────────────────────────────────────────
// MASSVISION Reap3r Bootstrap — Self-Healing Watchdog
// ──────────────────────────────────────────────────
//
// Responsibilities:
// 1. Ensure the reap3r-agent binary is present
// 2. Download/re-download if missing or corrupt
// 3. Verify SHA256 signature before execution
// 4. Launch agent as a subprocess
// 5. Restart agent if it crashes
// 6. Run as a system service (systemd/Windows Service)

use clap::Parser;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "reap3r-bootstrap", version, about = "MASSVISION Reap3r Bootstrap Watchdog")]
struct Args {
    /// Server base URL for downloading the agent binary
    #[arg(long, env = "REAP3R_SERVER_URL")]
    server_url: String,

    /// Path where the agent binary should be installed
    #[arg(long, default_value = default_agent_path(), env = "REAP3R_AGENT_PATH")]
    agent_path: String,

    /// Path to the agent configuration file
    #[arg(long, default_value = default_config_path(), env = "REAP3R_CONFIG_PATH")]
    config_path: String,

    /// Max consecutive failures before extended backoff
    #[arg(long, default_value = "5")]
    max_failures: u32,

    /// Restart delay in seconds
    #[arg(long, default_value = "5")]
    restart_delay: u64,
}

fn default_agent_path() -> &'static str {
    if cfg!(target_os = "windows") {
        "C:\\Program Files\\MASSVISION\\Reap3r\\reap3r-agent.exe"
    } else {
        "/opt/massvision/reap3r/reap3r-agent"
    }
}

fn default_config_path() -> &'static str {
    if cfg!(target_os = "windows") {
        "C:\\ProgramData\\MASSVISION\\Reap3r\\config.json"
    } else {
        "/etc/massvision/reap3r/config.json"
    }
}

#[derive(serde::Deserialize, Debug)]
struct AgentConfig {
    server: String,
    agent_id: Option<String>,
    agent_secret: Option<String>,
    enrollment_token: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct BinaryManifest {
    version: String,
    sha256: String,
    download_url: String,
    size: u64,
}

async fn verify_binary(path: &PathBuf, expected_hash: &str) -> bool {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let hash = hex::encode(hasher.finalize());
            hash == expected_hash
        }
        Err(_) => false,
    }
}

async fn download_binary(
    client: &reqwest::Client,
    url: &str,
    dest: &PathBuf,
    expected_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(url, "Downloading agent binary");

    let response = client.get(url).send().await?.error_for_status()?;
    let bytes = response.bytes().await?;

    // Verify hash before writing
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hex::encode(hasher.finalize());

    if hash != expected_hash {
        return Err(format!(
            "Hash mismatch: expected {}, got {}",
            expected_hash, hash
        )
        .into());
    }

    // Ensure parent directory exists
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    tokio::fs::write(dest, &bytes).await?;

    // Set executable permission on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(dest, perms)?;
    }

    info!("Agent binary downloaded and verified");
    Ok(())
}

async fn get_manifest(
    client: &reqwest::Client,
    server_url: &str,
) -> Result<BinaryManifest, Box<dyn std::error::Error>> {
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };

    let url = format!("{}/api/agent-binary/manifest?os={}&arch={}", server_url, os, arch);
    let manifest: BinaryManifest = client.get(&url).send().await?.json().await?;
    Ok(manifest)
}

async fn ensure_agent_binary(
    client: &reqwest::Client,
    server_url: &str,
    agent_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = get_manifest(client, server_url).await?;
    info!(version = %manifest.version, "Latest agent version");

    if agent_path.exists() {
        if verify_binary(agent_path, &manifest.sha256).await {
            info!("Agent binary is up to date");
            return Ok(());
        }
        warn!("Agent binary hash mismatch, re-downloading...");
    } else {
        info!("Agent binary not found, downloading...");
    }

    download_binary(client, &manifest.download_url, agent_path, &manifest.sha256).await
}

async fn run_agent(
    agent_path: &PathBuf,
    config: &AgentConfig,
) -> Result<std::process::ExitStatus, std::io::Error> {
    let mut cmd = tokio::process::Command::new(agent_path);
    cmd.arg("--server").arg(&config.server);

    if let Some(id) = &config.agent_id {
        cmd.arg("--agent-id").arg(id);
    }
    if let Some(secret) = &config.agent_secret {
        cmd.arg("--agent-secret").arg(secret);
    }
    if let Some(token) = &config.enrollment_token {
        cmd.arg("--token").arg(token);
    }

    let mut child = cmd.spawn()?;
    child.wait().await
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .json()
        .init();

    let args = Args::parse();
    info!("MASSVISION Reap3r Bootstrap starting");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("HTTP client");

    let agent_path = PathBuf::from(&args.agent_path);
    let mut consecutive_failures: u32 = 0;

    loop {
        // Try to ensure the agent binary is present and verified
        match ensure_agent_binary(&client, &args.server_url, &agent_path).await {
            Ok(()) => {}
            Err(e) => {
                error!(error = %e, "Failed to ensure agent binary");
                tokio::time::sleep(Duration::from_secs(args.restart_delay * 2)).await;
                continue;
            }
        }

        // Load config
        let config: AgentConfig = match tokio::fs::read_to_string(&args.config_path).await {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(c) => c,
                Err(e) => {
                    error!(error = %e, "Failed to parse config");
                    tokio::time::sleep(Duration::from_secs(args.restart_delay)).await;
                    continue;
                }
            },
            Err(e) => {
                error!(error = %e, config_path = %args.config_path, "Failed to read config");
                tokio::time::sleep(Duration::from_secs(args.restart_delay)).await;
                continue;
            }
        };

        // Run the agent
        info!("Starting agent process");
        match run_agent(&agent_path, &config).await {
            Ok(status) => {
                if status.success() {
                    info!("Agent exited normally");
                    consecutive_failures = 0;
                } else {
                    consecutive_failures += 1;
                    warn!(
                        exit_code = ?status.code(),
                        failures = consecutive_failures,
                        "Agent exited with error"
                    );
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                error!(error = %e, failures = consecutive_failures, "Failed to start agent");
            }
        }

        // Exponential backoff on repeated failures
        let delay = if consecutive_failures >= args.max_failures {
            warn!("Max consecutive failures reached, extended backoff");
            args.restart_delay * 12 // 60s default
        } else {
            args.restart_delay * (consecutive_failures as u64).max(1)
        };

        info!(delay_secs = delay, "Restarting agent in...");
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}
