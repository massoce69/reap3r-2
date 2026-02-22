use crate::protocol::{AgentMessage, MonitorInfo, RdInputPayload, RemoteDesktopStartPayload, StreamOutputPayload};
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{info, warn};

#[derive(Clone)]
pub struct RemoteDesktopManager {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    session_id: Option<String>,
    monitor: i32,
    stop_flag: Option<Arc<AtomicBool>>,
}

impl RemoteDesktopManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                session_id: None,
                monitor: -1,
                stop_flag: None,
            })),
        }
    }

    pub fn list_monitors(&self) -> Result<Vec<MonitorInfo>> {
        #[cfg(windows)]
        {
            return list_monitors_windows();
        }
        #[cfg(not(windows))]
        {
            Ok(vec![])
        }
    }

    pub fn start_stream(
        &self,
        agent_id: &str,
        session_id: &str,
        payload: RemoteDesktopStartPayload,
        ws_tx: mpsc::Sender<AgentMessage>,
    ) -> Result<()> {
        let _ = agent_id;
        // Stop existing session if any.
        self.stop_stream();

        let stop_flag = Arc::new(AtomicBool::new(false));
        {
            let mut inner = self.inner.lock().unwrap();
            inner.session_id = Some(session_id.to_string());
            inner.monitor = payload.monitor;
            inner.stop_flag = Some(stop_flag.clone());
        }

        let session_id = session_id.to_string();
        let fps = payload.fps.clamp(1, 15);
        let quality = payload.quality.clamp(10, 95);
        let scale = if payload.scale.is_finite() { payload.scale.clamp(0.1, 1.0) } else { 1.0 };
        let monitor = payload.monitor;

        tokio::task::spawn_blocking(move || {
            if let Err(e) = stream_loop_blocking(&session_id, monitor, fps, quality, scale, ws_tx, stop_flag) {
                warn!(error = %e, "Remote desktop stream loop failed");
            }
        });

        Ok(())
    }

    pub fn stop_stream(&self) {
        let flag = {
            let mut inner = self.inner.lock().unwrap();
            inner.session_id = None;
            inner.monitor = -1;
            inner.stop_flag.take()
        };
        if let Some(flag) = flag {
            flag.store(true, Ordering::Relaxed);
        }
    }

    pub fn handle_input(&self, input: RdInputPayload) {
        let (session_id_ok, monitor) = {
            let inner = self.inner.lock().unwrap();
            let ok = match (&inner.session_id, &input.session_id) {
                (Some(active), Some(req)) => active == req,
                (Some(_), None) => true,
                _ => false,
            };
            (ok, inner.monitor)
        };
        if !session_id_ok {
            return;
        }

        #[cfg(windows)]
        {
            if let Err(e) = inject_input_windows(&input, monitor) {
                warn!(error = %e, "RD input injection failed");
            }
        }
    }
}

fn stream_loop_blocking(
    session_id: &str,
    monitor: i32,
    fps: u32,
    quality: u8,
    scale: f32,
    ws_tx: mpsc::Sender<AgentMessage>,
    stop_flag: Arc<AtomicBool>,
) -> Result<()> {
    #[cfg(not(windows))]
    {
        let _ = monitor;
        let _ = fps;
        let _ = quality;
        let _ = scale;
        let msg = AgentMessage::StreamOutput(StreamOutputPayload {
            session_id: session_id.to_string(),
            stream_type: "error".into(),
            data: "remote_desktop unsupported on this platform".into(),
            sequence: 0,
        });
        let _ = ws_tx.blocking_send(msg);
        return Ok(());
    }

    #[cfg(windows)]
    {
        use scrap::{Capturer, Display};
        use std::io::ErrorKind;

        let mut displays = Display::all().context("Display::all")?;
        if displays.is_empty() {
            let msg = AgentMessage::StreamOutput(StreamOutputPayload {
                session_id: session_id.to_string(),
                stream_type: "error".into(),
                data: "no displays found".into(),
                sequence: 0,
            });
            let _ = ws_tx.blocking_send(msg);
            return Ok(());
        }
        let idx = if monitor >= 0 && (monitor as usize) < displays.len() { monitor as usize } else { 0 };
        let display = displays.remove(idx);

        let mut capturer = Capturer::new(display).context("Capturer::new")?;
        let w = capturer.width();
        let h = capturer.height();

        info!(width = w, height = h, fps = fps, quality = quality, scale = scale, "RD stream started");

        let frame_delay = Duration::from_millis((1000 / fps.max(1)) as u64);
        let mut seq: u64 = 0;

        while !stop_flag.load(Ordering::Relaxed) {
            let frame = match capturer.frame() {
                Ok(f) => f,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => {
                    let msg = AgentMessage::StreamOutput(StreamOutputPayload {
                        session_id: session_id.to_string(),
                        stream_type: "error".into(),
                        data: format!("capture error: {e}"),
                        sequence: seq,
                    });
                    let _ = ws_tx.blocking_send(msg);
                    break;
                }
            };

            let mut rgb = Vec::with_capacity(w * h * 3);
            for px in frame.chunks_exact(4) {
                rgb.push(px[2]);
                rgb.push(px[1]);
                rgb.push(px[0]);
            }

            let jpeg_bytes = encode_jpeg_rgb(&rgb, w as u32, h as u32, quality, scale)
                .context("encode_jpeg_rgb")?;

            let b64 = B64.encode(jpeg_bytes);
            let msg = AgentMessage::StreamOutput(StreamOutputPayload {
                session_id: session_id.to_string(),
                stream_type: "frame".into(),
                data: b64,
                sequence: seq,
            });
            if ws_tx.blocking_send(msg).is_err() {
                break;
            }
            seq = seq.wrapping_add(1);
            std::thread::sleep(frame_delay);
        }

        info!("RD stream stopped");
        Ok(())
    }
}

#[cfg(windows)]
fn encode_jpeg_rgb(rgb: &[u8], w: u32, h: u32, quality: u8, scale: f32) -> Result<Vec<u8>> {
    use image::{codecs::jpeg::JpegEncoder, imageops::FilterType, ImageBuffer, Rgb};
    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_raw(w, h, rgb.to_vec())
        .context("ImageBuffer::from_raw")?;

    let (out_w, out_h) = if (scale - 1.0).abs() > f32::EPSILON {
        let nw = ((w as f32) * scale).round().max(16.0) as u32;
        let nh = ((h as f32) * scale).round().max(16.0) as u32;
        (nw, nh)
    } else {
        (w, h)
    };

    let resized = if out_w != w || out_h != h {
        image::imageops::resize(&img, out_w, out_h, FilterType::Triangle)
    } else {
        img
    };

    let mut out = Vec::new();
    let mut enc = JpegEncoder::new_with_quality(&mut out, quality);
    enc.encode_image(&resized).context("jpeg encode")?;
    Ok(out)
}

#[cfg(windows)]
fn list_monitors_windows() -> Result<Vec<MonitorInfo>> {
    use windows::Win32::Foundation::{BOOL, LPARAM, RECT};
    use windows::Win32::Graphics::Gdi::{EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFOEXW};

    let mut out: Vec<MonitorInfo> = Vec::new();

    unsafe extern "system" fn enum_proc(
        hmon: HMONITOR,
        _hdc: HDC,
        _rc: *mut RECT,
        lparam: LPARAM,
    ) -> BOOL {
        let vec_ptr = lparam.0 as *mut Vec<MonitorInfo>;
        if vec_ptr.is_null() {
            return BOOL(0);
        }
        let vec = &mut *vec_ptr;
        let mut info = MONITORINFOEXW::default();
        info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
        if GetMonitorInfoW(hmon, &mut info as *mut _ as *mut _).as_bool() {
            let r = info.monitorInfo.rcMonitor;
            let primary = (info.monitorInfo.dwFlags & 1) == 1;
            let name = String::from_utf16_lossy(&info.szDevice);
            let name = name.trim_end_matches('\0').to_string();
            vec.push(MonitorInfo {
                index: (vec.len() as i32),
                name,
                primary,
                x: r.left,
                y: r.top,
                width: r.right - r.left,
                height: r.bottom - r.top,
            });
        }
        BOOL(1)
    }

    unsafe {
        EnumDisplayMonitors(None, None, Some(enum_proc), LPARAM((&mut out as *mut _) as isize))
            .ok()
            .context("EnumDisplayMonitors")?;
    }

    Ok(out)
}

#[cfg(windows)]
fn inject_input_windows(input: &RdInputPayload, _monitor: i32) -> Result<()> {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::Input::KeyboardAndMouse::*;
    use windows::Win32::UI::WindowsAndMessaging::{GetCursorPos, GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN};

    let input_type = input.input_type.as_str();
    unsafe {
        match input_type {
            "mouse_move" => {
                let x = input.x.unwrap_or(0.5).clamp(0.0, 1.0);
                let y = input.y.unwrap_or(0.5).clamp(0.0, 1.0);
                let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
                let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
                let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1);
                let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1);

                let px = vx + ((vw as f32) * x) as i32;
                let py = vy + ((vh as f32) * y) as i32;

                // Absolute coordinates are 0..65535 across virtual screen
                let ax = (((px - vx) as f32) * 65535.0 / (vw as f32)).round() as i32;
                let ay = (((py - vy) as f32) * 65535.0 / (vh as f32)).round() as i32;

                let mut mi = MOUSEINPUT {
                    dx: ax,
                    dy: ay,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                    time: 0,
                    dwExtraInfo: 0,
                };
                let mut inp = INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 { mi },
                };
                SendInput(&[inp], std::mem::size_of::<INPUT>() as i32);
            }
            "mouse_down" | "mouse_up" => {
                let button = input.button.as_deref().unwrap_or("left");
                let down = input_type == "mouse_down";
                let flag = match (button, down) {
                    ("left", true) => MOUSEEVENTF_LEFTDOWN,
                    ("left", false) => MOUSEEVENTF_LEFTUP,
                    ("right", true) => MOUSEEVENTF_RIGHTDOWN,
                    ("right", false) => MOUSEEVENTF_RIGHTUP,
                    ("middle", true) => MOUSEEVENTF_MIDDLEDOWN,
                    ("middle", false) => MOUSEEVENTF_MIDDLEUP,
                    _ => MOUSEEVENTF_LEFTDOWN,
                };
                let mut mi = MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: flag,
                    time: 0,
                    dwExtraInfo: 0,
                };
                let mut inp = INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 { mi },
                };
                SendInput(&[inp], std::mem::size_of::<INPUT>() as i32);
            }
            "mouse_wheel" => {
                let delta = input.delta.unwrap_or(0);
                const WHEEL_DELTA_I32: i32 = 120;
                let mut mi = MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: (delta * WHEEL_DELTA_I32) as u32,
                    dwFlags: MOUSEEVENTF_WHEEL,
                    time: 0,
                    dwExtraInfo: 0,
                };
                let mut inp = INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 { mi },
                };
                SendInput(&[inp], std::mem::size_of::<INPUT>() as i32);
            }
            "key_down" | "key_up" => {
                let vk = input.vk.unwrap_or(0);
                if vk == 0 {
                    return Ok(());
                }
                let keyup = input_type == "key_up";
                let flags = if keyup { KEYEVENTF_KEYUP } else { KEYBD_EVENT_FLAGS(0) };
                let mut ki = KEYBDINPUT {
                    wVk: VIRTUAL_KEY(vk),
                    wScan: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                };
                let mut inp = INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 { ki },
                };
                SendInput(&[inp], std::mem::size_of::<INPUT>() as i32);
            }
            _ => {
                // ignore
            }
        }

        // keep compiler happy with imported but unused functions in some builds
        let mut p = POINT { x: 0, y: 0 };
        let _ = GetCursorPos(&mut p);
    }

    Ok(())
}
