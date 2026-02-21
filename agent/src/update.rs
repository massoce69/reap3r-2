// ─────────────────────────────────────────────────────────────
// update.rs – Atomic Update Manager
//   • Download to staging
//   • SHA-256 hash verification
//   • Ed25519 signature verification
//   • Atomic binary swap (platform-specific)
//   • Health check after update
//   • Automatic rollback on failure
//   • Repair update (individual module download)
// ─────────────────────────────────────────────────────────────
use anyhow::{Result, Context};
use sha2::{Sha256, Digest};
use std::path::PathBuf;
use tracing::{error, info, warn};

use crate::agent::AgentConfig;
use crate::network::ApiClient;
use crate::platform;
use crate::protocol::*;
use crate::security::SignatureVerifier;
use crate::storage::Database;

// ═══════════════════════════════════════════════════════════════
//  Update Manager
// ═══════════════════════════════════════════════════════════════
pub struct UpdateManager {
    config: AgentConfig,
    api: ApiClient,
    db: Database,
}

impl UpdateManager {
    pub fn new(config: AgentConfig, api: ApiClient, db: Database) -> Self {
        Self { config, api, db }
    }

    /// Full update flow: download → verify → swap → healthcheck → rollback if fail
    pub async fn apply_update(
        &mut self,
        notification: &UpdateNotification,
        agent_id: &str,
    ) -> Result<()> {
        info!(
            version = %notification.version,
            mandatory = notification.mandatory,
            "Starting update process"
        );

        // 1. Download manifest
        let manifest = self.download_manifest(&notification.manifest_url).await?;
        info!(version = %manifest.version, size = manifest.size_bytes, "Manifest downloaded");

        // 2. Check min_agent_version compatibility
        if let Some(ref min_ver) = manifest.min_agent_version {
            let current = env!("CARGO_PKG_VERSION");
            if !version_compatible(current, min_ver) {
                anyhow::bail!(
                    "Current version {current} < minimum required {min_ver}"
                );
            }
        }

        // 3. Download binary to staging
        let staging_dir = if self.config.update.staging_dir.is_empty() {
            platform::get_staging_dir()
        } else {
            PathBuf::from(&self.config.update.staging_dir)
        };
        std::fs::create_dir_all(&staging_dir)?;

        #[cfg(not(windows))]
        let staged_binary = staging_dir.join("massvision-agent-new");
        #[cfg(windows)]
        let staged_binary = staging_dir.join("massvision-agent-new.exe");

        info!(url = %manifest.download_url, "Downloading update binary");
        self.api.download_file(&manifest.download_url, &staged_binary).await
            .context("downloading update binary")?;

        // 4. Verify SHA-256
        info!("Verifying SHA-256 hash");
        let actual_hash = hash_file(&staged_binary)?;
        if actual_hash != manifest.sha256 {
            std::fs::remove_file(&staged_binary).ok();
            anyhow::bail!(
                "SHA-256 mismatch: expected={}, actual={actual_hash}",
                manifest.sha256
            );
        }
        info!("SHA-256 verified ✓");

        // 5. Verify Ed25519 signature
        if self.config.security.verify_signatures {
            info!("Verifying Ed25519 signature");
            let verifier = SignatureVerifier::from_credentials()
                .context("loading server public key for signature verification")?;
            let binary_data = std::fs::read(&staged_binary)?;
            if !verifier.verify(&binary_data, &manifest.signature)? {
                std::fs::remove_file(&staged_binary).ok();
                anyhow::bail!("Ed25519 signature verification FAILED");
            }
            info!("Signature verified ✓");
        }

        // 6. Atomic swap
        let current_exe = std::env::current_exe()?;
        info!(
            from = %staged_binary.display(),
            to = %current_exe.display(),
            "Performing atomic binary swap"
        );
        platform::atomic_binary_swap(&staged_binary, &current_exe)
            .context("atomic binary swap")?;
        info!("Binary swapped ✓");

        // 7. Save binary manifest for tamper detection
        let manifest_json = serde_json::json!({
            "version": manifest.version,
            "sha256": manifest.sha256,
            "updated_at": chrono::Utc::now().to_rfc3339(),
        });
        let manifest_path = platform::get_data_dir().join("binary_manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest_json)?)?;

        // 8. Health check
        info!("Running post-update health check");
        match self.health_check().await {
            Ok(()) => {
                info!(version = %manifest.version, "Update applied successfully ✓");
                // Audit
                self.db.log_audit(&AuditEvent {
                    event_type: AuditEventType::UpdateApplied,
                    agent_id: agent_id.to_string(),
                    operator_id: None,
                    details: serde_json::json!({
                        "version": manifest.version,
                        "sha256": manifest.sha256,
                    }),
                    timestamp: chrono::Utc::now(),
                }).ok();
                // Clean up staging
                std::fs::remove_file(&staged_binary).ok();
            }
            Err(e) => {
                error!(error = %e, "Health check failed — rolling back");
                if self.config.update.rollback_on_failure {
                    self.rollback(&current_exe, agent_id).await?;
                }
                anyhow::bail!("Update health check failed: {e}");
            }
        }

        // 9. Update module manifests in DB
        for module in &manifest.modules {
            self.db.save_module_manifest(
                &module.name,
                &module.version,
                &module.sha256,
                "updated",
            )?;
        }

        Ok(())
    }

    /// Repair update: download and replace a single module
    #[allow(dead_code)]
    pub async fn repair_module(
        &mut self,
        module_name: &str,
        module_manifest: &ModuleManifestEntry,
        _agent_id: &str,
    ) -> Result<()> {
        info!(module = module_name, version = %module_manifest.version, "Repairing module");

        let modules_dir = platform::get_modules_dir();
        std::fs::create_dir_all(&modules_dir)?;

        let module_path = modules_dir.join(module_name);
        let staging_path = platform::get_staging_dir().join(format!("{module_name}.staging"));

        // Download
        self.api.download_file(&module_manifest.download_url, &staging_path).await?;

        // Verify hash
        let actual_hash = hash_file(&staging_path)?;
        if actual_hash != module_manifest.sha256 {
            std::fs::remove_file(&staging_path).ok();
            anyhow::bail!(
                "Module {module_name} hash mismatch: expected={}, actual={actual_hash}",
                module_manifest.sha256
            );
        }

        // Swap
        if module_path.exists() {
            let backup = platform::get_rollback_dir().join(module_name);
            std::fs::copy(&module_path, &backup)?;
        }
        std::fs::rename(&staging_path, &module_path)?;

        // Update DB
        self.db.save_module_manifest(
            module_name,
            &module_manifest.version,
            &module_manifest.sha256,
            "repaired",
        )?;

        info!(module = module_name, "Module repaired ✓");
        Ok(())
    }

    // ── Private helpers ──────────────────────────────────────

    async fn download_manifest(&self, url: &str) -> Result<UpdateManifest> {
        let client = reqwest::Client::new();
        let resp = client.get(url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Manifest download failed: HTTP {}", resp.status());
        }
        let manifest: UpdateManifest = resp.json().await?;
        Ok(manifest)
    }

    async fn health_check(&self) -> Result<()> {
        // Basic health check: verify the new binary can respond to --version
        let exe = std::env::current_exe()?;
        let output = tokio::process::Command::new(&exe)
            .arg("status")
            .output()
            .await;

        match output {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                anyhow::bail!("Health check exit code {}: {stderr}", o.status)
            }
            Err(e) => anyhow::bail!("Health check failed to execute: {e}"),
        }
    }

    async fn rollback(&self, target: &std::path::Path, agent_id: &str) -> Result<()> {
        warn!("Rolling back binary update");
        platform::rollback_binary(target)?;

        self.db.log_audit(&AuditEvent {
            event_type: AuditEventType::UpdateRolledBack,
            agent_id: agent_id.to_string(),
            operator_id: None,
            details: serde_json::json!({"reason": "health_check_failed"}),
            timestamp: chrono::Utc::now(),
        }).ok();

        info!("Rollback completed ✓");
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════════

fn hash_file(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}

/// Simple semver compatibility check: current >= minimum
fn version_compatible(current: &str, minimum: &str) -> bool {
    let parse = |v: &str| -> (u32, u32, u32) {
        let parts: Vec<u32> = v.split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    };
    let cur = parse(current);
    let min = parse(minimum);
    cur >= min
}

// ═══════════════════════════════════════════════════════════════
//  Staged Rollout Helper (server-side, but agent-side check)
// ═══════════════════════════════════════════════════════════════
#[allow(dead_code)]
pub fn should_apply_update(machine_id: &str, rollout_percentage: u8) -> bool {
    if rollout_percentage >= 100 {
        return true;
    }
    // Deterministic bucket based on machine_id hash
    let hash = Sha256::digest(machine_id.as_bytes());
    let bucket = hash[0] as u16 * 100 / 256;
    bucket < rollout_percentage as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_compatible() {
        assert!(version_compatible("2.0.0", "1.0.0"));
        assert!(version_compatible("2.0.0", "2.0.0"));
        assert!(!version_compatible("1.9.9", "2.0.0"));
        assert!(version_compatible("2.1.0", "2.0.5"));
    }

    #[test]
    fn test_rollout_deterministic() {
        let id = "test-machine-12345";
        let result1 = should_apply_update(id, 50);
        let result2 = should_apply_update(id, 50);
        assert_eq!(result1, result2, "Rollout must be deterministic");
    }

    #[test]
    fn test_rollout_100_always_applies() {
        assert!(should_apply_update("any-machine", 100));
    }
}
