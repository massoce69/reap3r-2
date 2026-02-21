// ─────────────────────────────────────────────────────────────
// modules/webcam.rs – Camera capture for industrial monitoring
//   • Periodic or on-demand frame capture from connected cameras
//   • Uses ffmpeg (cross-platform) for capture
//   • JPEG output, configurable resolution & quality
//   • Camera enumeration
//   • Full audit trail of every capture
//   • Uploads snapshots to MassVision server via HTTP
// ─────────────────────────────────────────────────────────────
use anyhow::{Result, Context};
use chrono::Utc;
use std::path::PathBuf;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::agent::AgentConfig;
use crate::network::ApiClient;
use crate::protocol::*;
use crate::security::TokenManager;
use crate::storage::Database;

// ═══════════════════════════════════════════════════════════════
//  Camera info
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CameraInfo {
    pub device_index: u32,
    pub device_name: String,
    pub device_path: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaptureRequest {
    /// Camera device index (0 = default)
    pub camera_index: u32,
    /// Output resolution width (0 = native)
    pub width: u32,
    /// Output resolution height (0 = native)
    pub height: u32,
    /// JPEG quality 1-100
    pub quality: u8,
    /// Optional label (e.g. "robot_arm_3", "conveyor_belt_2")
    pub label: Option<String>,
}

impl Default for CaptureRequest {
    fn default() -> Self {
        Self {
            camera_index: 0,
            width: 1280,
            height: 720,
            quality: 85,
            label: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaptureResult {
    pub agent_id: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub camera_index: u32,
    pub label: Option<String>,
    pub width: u32,
    pub height: u32,
    pub file_size_bytes: u64,
    /// Base64-encoded JPEG image
    pub image_base64: String,
    pub success: bool,
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
//  Periodic webcam collector (captures at fixed interval)
// ═══════════════════════════════════════════════════════════════
pub struct WebcamCollector {
    config: AgentConfig,
    api: ApiClient,
    token_mgr: TokenManager,
    db: Database,
    shutdown: broadcast::Receiver<()>,
}

impl WebcamCollector {
    pub fn new(
        config: AgentConfig,
        api: ApiClient,
        token_mgr: TokenManager,
        db: Database,
        shutdown: broadcast::Receiver<()>,
    ) -> Self {
        Self { config, api, token_mgr, db, shutdown }
    }

    pub async fn run(mut self) {
        let interval_secs = self.config.modules.webcam_interval_secs;
        info!(interval_secs, "Webcam collector started");

        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {}
                _ = self.shutdown.recv() => {
                    info!("Webcam collector shutting down");
                    return;
                }
            }

            let request = CaptureRequest {
                camera_index: self.config.modules.webcam_default_camera,
                width: self.config.modules.webcam_width,
                height: self.config.modules.webcam_height,
                quality: self.config.modules.webcam_quality,
                label: Some("periodic".to_string()),
            };

            let result = capture_frame(
                &request,
                self.token_mgr.agent_id(),
            ).await;

            // Audit
            self.db.log_audit(&AuditEvent {
                event_type: AuditEventType::WebcamCapture,
                agent_id: self.token_mgr.agent_id().to_string(),
                operator_id: None,
                details: serde_json::json!({
                    "camera_index": request.camera_index,
                    "label": request.label,
                    "success": result.success,
                }),
                timestamp: Utc::now(),
            }).ok();

            if result.success {
                if let Err(e) = self.api.send_webcam_capture(&result).await {
                    warn!(error = %e, "Failed to upload webcam snapshot");
                } else {
                    debug!(size = result.file_size_bytes, "Webcam snapshot sent");
                }
            } else {
                warn!(error = ?result.error, "Webcam capture failed");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  On-demand capture (called from job processor)
// ═══════════════════════════════════════════════════════════════
pub async fn execute_webcam_job(
    job: &JobAssignment,
    agent_id: &str,
    api: &ApiClient,
    db: &Database,
) -> JobResult {
    let started_at = Utc::now();

    let request: CaptureRequest = serde_json::from_value(job.payload.clone())
        .unwrap_or_default();

    info!(
        job_id = %job.job_id,
        camera = request.camera_index,
        label = ?request.label,
        "On-demand webcam capture"
    );

    let result = capture_frame(&request, agent_id).await;

    // Audit
    db.log_audit(&AuditEvent {
        event_type: AuditEventType::WebcamCapture,
        agent_id: agent_id.to_string(),
        operator_id: None,
        details: serde_json::json!({
            "job_id": job.job_id,
            "camera_index": request.camera_index,
            "label": request.label,
            "success": result.success,
        }),
        timestamp: Utc::now(),
    }).ok();

    if result.success {
        // Upload image
        if let Err(e) = api.send_webcam_capture(&result).await {
            error!(error = %e, "Failed to upload webcam capture");
            return JobResult {
                job_id: job.job_id.clone(),
                agent_id: agent_id.to_string(),
                status: JobStatus::Failed,
                exit_code: Some(1),
                stdout: None,
                stderr: Some(format!("Upload failed: {e}")),
                artifacts: Vec::new(),
                started_at,
                completed_at: Utc::now(),
                duration_ms: (Utc::now() - started_at).num_milliseconds() as u64,
            };
        }

        JobResult {
            job_id: job.job_id.clone(),
            agent_id: agent_id.to_string(),
            status: JobStatus::Success,
            exit_code: Some(0),
            stdout: Some(serde_json::to_string(&serde_json::json!({
                "camera_index": result.camera_index,
                "width": result.width,
                "height": result.height,
                "file_size_bytes": result.file_size_bytes,
                "label": result.label,
            })).unwrap_or_default()),
            stderr: None,
            artifacts: Vec::new(),
            started_at,
            completed_at: Utc::now(),
            duration_ms: (Utc::now() - started_at).num_milliseconds() as u64,
        }
    } else {
        JobResult {
            job_id: job.job_id.clone(),
            agent_id: agent_id.to_string(),
            status: JobStatus::Failed,
            exit_code: Some(1),
            stdout: None,
            stderr: result.error,
            artifacts: Vec::new(),
            started_at,
            completed_at: Utc::now(),
            duration_ms: (Utc::now() - started_at).num_milliseconds() as u64,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Camera enumeration
// ═══════════════════════════════════════════════════════════════
pub fn list_cameras() -> Vec<CameraInfo> {
    let mut cameras = Vec::new();

    #[cfg(target_os = "windows")]
    {
        // Use ffmpeg to list DirectShow devices
        if let Ok(output) = std::process::Command::new("ffmpeg")
            .args(["-list_devices", "true", "-f", "dshow", "-i", "dummy"])
            .output()
        {
            // ffmpeg outputs device list on stderr
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut index = 0u32;
            for line in stderr.lines() {
                if line.contains("(video)") {
                    // Extract device name between quotes
                    if let Some(start) = line.find('"') {
                        if let Some(end) = line[start + 1..].find('"') {
                            let name = &line[start + 1..start + 1 + end];
                            cameras.push(CameraInfo {
                                device_index: index,
                                device_name: name.to_string(),
                                device_path: format!("video={name}"),
                            });
                            index += 1;
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Enumerate /dev/video* devices
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("video") {
                    if let Ok(idx) = name_str.trim_start_matches("video").parse::<u32>() {
                        let path = format!("/dev/{name_str}");
                        // Try to get device name via v4l2
                        let device_name = get_v4l2_device_name(&path)
                            .unwrap_or_else(|| format!("Camera {idx}"));
                        cameras.push(CameraInfo {
                            device_index: idx,
                            device_name,
                            device_path: path,
                        });
                    }
                }
            }
        }
        cameras.sort_by_key(|c| c.device_index);
    }

    #[cfg(target_os = "macos")]
    {
        // Use ffmpeg to list AVFoundation devices
        if let Ok(output) = std::process::Command::new("ffmpeg")
            .args(["-f", "avfoundation", "-list_devices", "true", "-i", ""])
            .output()
        {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut index = 0u32;
            let mut in_video = false;
            for line in stderr.lines() {
                if line.contains("AVFoundation video devices") {
                    in_video = true;
                    continue;
                }
                if line.contains("AVFoundation audio devices") {
                    break;
                }
                if in_video {
                    // Lines like: [AVFoundation ...] [0] FaceTime HD Camera
                    if let Some(bracket_end) = line.rfind(']') {
                        let name = line[bracket_end + 1..].trim().to_string();
                        if !name.is_empty() {
                            cameras.push(CameraInfo {
                                device_index: index,
                                device_name: name,
                                device_path: format!("{index}"),
                            });
                            index += 1;
                        }
                    }
                }
            }
        }
    }

    cameras
}

#[cfg(target_os = "linux")]
fn get_v4l2_device_name(device_path: &str) -> Option<String> {
    let output = std::process::Command::new("v4l2-ctl")
        .args(["--device", device_path, "--info"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("Card type") {
            return Some(line.split(':').nth(1)?.trim().to_string());
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════
//  Core capture function (uses ffmpeg)
// ═══════════════════════════════════════════════════════════════
pub async fn capture_frame(
    request: &CaptureRequest,
    agent_id: &str,
) -> CaptureResult {
    let timestamp = Utc::now();
    let tmpdir = std::env::temp_dir().join("massvision_webcam");
    std::fs::create_dir_all(&tmpdir).ok();

    let filename = format!(
        "capture_{}_cam{}_{}.jpg",
        agent_id,
        request.camera_index,
        timestamp.format("%Y%m%d_%H%M%S")
    );
    let output_path = tmpdir.join(&filename);

    // Build ffmpeg command based on platform
    let result = capture_with_ffmpeg(request, &output_path).await;

    match result {
        Ok(()) => {
            // Read the captured file
            match std::fs::read(&output_path) {
                Ok(data) => {
                    let file_size = data.len() as u64;
                    let image_base64 = base64_encode(&data);

                    // Detect actual resolution from the image (use requested as fallback)
                    let (w, h) = detect_jpeg_dimensions(&data)
                        .unwrap_or((request.width, request.height));

                    // Clean up temp file
                    std::fs::remove_file(&output_path).ok();

                    info!(
                        camera = request.camera_index,
                        size_kb = file_size / 1024,
                        resolution = format!("{w}x{h}"),
                        "Camera frame captured"
                    );

                    CaptureResult {
                        agent_id: agent_id.to_string(),
                        timestamp,
                        camera_index: request.camera_index,
                        label: request.label.clone(),
                        width: w,
                        height: h,
                        file_size_bytes: file_size,
                        image_base64,
                        success: true,
                        error: None,
                    }
                }
                Err(e) => {
                    std::fs::remove_file(&output_path).ok();
                    CaptureResult {
                        agent_id: agent_id.to_string(),
                        timestamp,
                        camera_index: request.camera_index,
                        label: request.label.clone(),
                        width: 0,
                        height: 0,
                        file_size_bytes: 0,
                        image_base64: String::new(),
                        success: false,
                        error: Some(format!("Failed to read capture file: {e}")),
                    }
                }
            }
        }
        Err(e) => {
            std::fs::remove_file(&output_path).ok();
            CaptureResult {
                agent_id: agent_id.to_string(),
                timestamp,
                camera_index: request.camera_index,
                label: request.label.clone(),
                width: 0,
                height: 0,
                file_size_bytes: 0,
                image_base64: String::new(),
                success: false,
                error: Some(format!("{e}")),
            }
        }
    }
}

async fn capture_with_ffmpeg(
    request: &CaptureRequest,
    output_path: &PathBuf,
) -> Result<()> {
    let output_str = output_path.to_string_lossy().to_string();

    // Build resolution filter if specified
    let scale_filter = if request.width > 0 && request.height > 0 {
        format!("-vf scale={}:{}", request.width, request.height)
    } else {
        String::new()
    };

    let quality = request.quality.clamp(1, 31); // ffmpeg mjpeg quality 2-31 (lower=better)
    let ffmpeg_quality = 2 + ((100 - quality as u32) * 29 / 100); // map 1-100 to 31-2

    #[cfg(target_os = "windows")]
    let args = {
        // Detect input device name
        let cameras = list_cameras();
        let device_name = cameras
            .iter()
            .find(|c| c.device_index == request.camera_index)
            .map(|c| c.device_path.clone())
            .unwrap_or_else(|| format!("video=Integrated Camera"));

        let mut a = vec![
            "-f".to_string(), "dshow".to_string(),
            "-i".to_string(), device_name,
            "-frames:v".to_string(), "1".to_string(),
            "-q:v".to_string(), ffmpeg_quality.to_string(),
        ];
        if !scale_filter.is_empty() {
            a.extend(["-vf".to_string(), format!("scale={}:{}", request.width, request.height)]);
        }
        a.extend([
            "-y".to_string(),
            output_str.clone(),
        ]);
        a
    };

    #[cfg(target_os = "linux")]
    let args = {
        let device = format!("/dev/video{}", request.camera_index);
        let mut a = vec![
            "-f".to_string(), "v4l2".to_string(),
            "-i".to_string(), device,
            "-frames:v".to_string(), "1".to_string(),
            "-q:v".to_string(), ffmpeg_quality.to_string(),
        ];
        if !scale_filter.is_empty() {
            a.extend(["-vf".to_string(), format!("scale={}:{}", request.width, request.height)]);
        }
        a.extend([
            "-y".to_string(),
            output_str.clone(),
        ]);
        a
    };

    #[cfg(target_os = "macos")]
    let args = {
        let mut a = vec![
            "-f".to_string(), "avfoundation".to_string(),
            "-i".to_string(), format!("{}", request.camera_index),
            "-frames:v".to_string(), "1".to_string(),
            "-q:v".to_string(), ffmpeg_quality.to_string(),
        ];
        if !scale_filter.is_empty() {
            a.extend(["-vf".to_string(), format!("scale={}:{}", request.width, request.height)]);
        }
        a.extend([
            "-y".to_string(),
            output_str.clone(),
        ]);
        a
    };

    debug!(args = ?args, "ffmpeg capture command");

    let output = tokio::process::Command::new("ffmpeg")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn ffmpeg. Is ffmpeg installed and in PATH?")?
        .wait_with_output()
        .await
        .context("ffmpeg execution failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "ffmpeg exited with code {}: {}",
            output.status.code().unwrap_or(-1),
            stderr.lines().last().unwrap_or("unknown error")
        );
    }

    // Verify the file was created
    if !output_path.exists() {
        anyhow::bail!("ffmpeg completed but output file was not created");
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════

/// Base64 encode bytes (standard, no padding)
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Try to extract JPEG dimensions from SOF0/SOF2 markers (best-effort)
fn detect_jpeg_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    // JPEG SOF markers: 0xFFC0 (SOF0) or 0xFFC2 (SOF2)
    let len = data.len();
    let mut i = 0;
    while i + 1 < len {
        if data[i] == 0xFF {
            let marker = data[i + 1];
            // SOF0 or SOF2 — contains dimensions
            if marker == 0xC0 || marker == 0xC2 {
                if i + 9 < len {
                    let height = u16::from_be_bytes([data[i + 5], data[i + 6]]) as u32;
                    let width = u16::from_be_bytes([data[i + 7], data[i + 8]]) as u32;
                    return Some((width, height));
                }
            }
            // Standalone markers (no length field): SOI, EOI, RST0-7, TEM
            if marker == 0xD8 || marker == 0xD9 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01 || marker == 0x00 || marker == 0xFF {
                i += 2;
            } else if i + 3 < len {
                // Markers with length field
                let seg_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                i += 2 + seg_len;
            } else {
                break;
            }
        } else {
            i += 1;
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_capture_request() {
        let req = CaptureRequest::default();
        assert_eq!(req.camera_index, 0);
        assert_eq!(req.width, 1280);
        assert_eq!(req.height, 720);
        assert_eq!(req.quality, 85);
        assert!(req.label.is_none());
    }

    #[test]
    fn test_jpeg_dimension_detection() {
        // Minimal valid JPEG with SOF0 marker
        // FF D8 (SOI) FF C0 (SOF0) 00 0B (length=11) 08 (precision)
        // 00 F0 (height=240) 01 40 (width=320) 03 (components) ...
        let fake_jpeg = vec![
            0xFF, 0xD8,                   // SOI
            0xFF, 0xC0,                   // SOF0
            0x00, 0x0B,                   // Length
            0x08,                         // Precision
            0x00, 0xF0,                   // Height = 240
            0x01, 0x40,                   // Width = 320
            0x03,                         // Num components
            0x01, 0x22, 0x00,            // Component data
        ];
        let dims = detect_jpeg_dimensions(&fake_jpeg);
        assert_eq!(dims, Some((320, 240)));
    }

    #[test]
    fn test_base64_encode() {
        let data = b"hello webcam";
        let encoded = base64_encode(data);
        assert!(!encoded.is_empty());
        assert!(encoded.len() > data.len()); // base64 is always larger
    }

    #[test]
    fn test_camera_list_does_not_panic() {
        // Just verify it doesn't crash
        let _cameras = list_cameras();
    }
}
