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

        // ── Diagnostic: report PID ────────────────────────────────────────────
        let own_pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
        info!(pid = own_pid, "RD stream starting; binding to interactive desktop");
        let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
            session_id: session_id.to_string(),
            stream_type: "debug".into(),
            data: format!("capture start: pid={own_pid} monitor={monitor}"),
            sequence: 0,
        }));

        // ── Bind to interactive desktop FIRST ─────────────────────────────────
        bind_to_interactive_desktop();

        // ── Strategy 1: scrap (DXGI via OS-managed duplication) ───────────────
        let mut displays = Display::all().unwrap_or_default();

        if !displays.is_empty() {
            info!(display_count = displays.len(), pid = own_pid, "DXGI (scrap) found displays");
            let idx = if monitor >= 0 && (monitor as usize) < displays.len() { monitor as usize } else { 0 };
            let display = displays.remove(idx);

            let mut capturer = match Capturer::new(display) {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "scrap Capturer::new failed; will try direct DXGI");
                    return dxgi_direct_stream_loop_blocking(session_id, monitor, fps, quality, scale, &ws_tx, &stop_flag);
                }
            };
            let w = capturer.width();
            let h = capturer.height();

            info!(backend = "scrap", width = w, height = h, fps, quality, scale, "RD stream started");

            let frame_delay = Duration::from_millis((1000 / fps.max(1)) as u64);
            let mut seq: u64 = 1;

            loop {
                if stop_flag.load(Ordering::Relaxed) { break; }
                let frame = match capturer.frame() {
                    Ok(f) => f,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => {
                        let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
                            session_id: session_id.to_string(),
                            stream_type: "error".into(),
                            data: format!("scrap capture error: {e}"),
                            sequence: seq,
                        }));
                        break;
                    }
                };

                // BGRA → RGB
                let mut rgb = Vec::with_capacity(w * h * 3);
                for px in frame.chunks_exact(4) {
                    rgb.push(px[2]);
                    rgb.push(px[1]);
                    rgb.push(px[0]);
                }

                let jpeg_bytes = encode_jpeg_rgb(&rgb, w as u32, h as u32, quality, scale)
                    .context("encode_jpeg_rgb")?;
                let b64 = B64.encode(jpeg_bytes);
                if ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
                    session_id: session_id.to_string(),
                    stream_type: "frame".into(),
                    data: b64,
                    sequence: seq,
                })).is_err() { break; }
                seq = seq.wrapping_add(1);
                std::thread::sleep(frame_delay);
            }

            info!(backend = "scrap", "RD stream stopped");
            return Ok(());
        }

        // ── Strategy 2: direct IDXGIOutputDuplication (works in any session) ──
        info!("scrap found 0 displays; trying direct DXGI OutputDuplication");
        let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
            session_id: session_id.to_string(),
            stream_type: "debug".into(),
            data: format!("scrap=0 displays, pid={own_pid}: trying direct DXGI"),
            sequence: 0,
        }));
        match dxgi_direct_stream_loop_blocking(session_id, monitor, fps, quality, scale, &ws_tx, &stop_flag) {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!(error = %e, "Direct DXGI failed; falling back to GDI");
                let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
                    session_id: session_id.to_string(),
                    stream_type: "debug".into(),
                    data: format!("direct DXGI failed: {e}; trying GDI (may be black on Win10/11 DWM)"),
                    sequence: 0,
                }));
            }
        }

        // ── Strategy 3: GDI BitBlt (last resort, may be black on Win10/11) ───
        gdi_stream_loop_blocking(session_id, monitor, fps, quality, scale, ws_tx, stop_flag)
    }
}

/// Direct IDXGIOutputDuplication screen capture.
/// This is the correct API for Windows 10/11 where DWM composites in GPU memory.
/// Works from any session once the process token has access to the adapter.
#[cfg(windows)]
fn dxgi_direct_stream_loop_blocking(
    session_id: &str,
    monitor: i32,
    fps: u32,
    quality: u8,
    scale: f32,
    ws_tx: &mpsc::Sender<AgentMessage>,
    stop_flag: &Arc<AtomicBool>,
) -> Result<()> {
    use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
    use windows::core::Interface;
    use windows::Win32::Graphics::Direct3D11::{
        D3D11CreateDevice, D3D11_CREATE_DEVICE_FLAG, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ,
        D3D11_SDK_VERSION, D3D11_SUBRESOURCE_DATA, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
        ID3D11Device, ID3D11DeviceContext, ID3D11Resource, ID3D11Texture2D,
    };
    use windows::Win32::Graphics::Dxgi::{
        IDXGIAdapter, IDXGIDevice, IDXGIOutput, IDXGIOutput1, IDXGIResource,
        DXGI_OUTDUPL_FRAME_INFO,
    };
    use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};

    // DXGI error codes
    const DXGI_ERROR_WAIT_TIMEOUT: i32 = 0x887A0027u32 as i32; // no new frame yet
    const DXGI_ERROR_ACCESS_LOST:  i32 = 0x887A0026u32 as i32; // display mode changed
    const DXGI_ERROR_DEVICE_RESET: i32 = 0x887A0007u32 as i32;

    unsafe {
        // ── 1. Create D3D11 hardware device ───────────────────────────────────
        let mut device: Option<ID3D11Device> = None;
        let mut ctx_opt: Option<ID3D11DeviceContext> = None;
        D3D11CreateDevice(
            None::<&IDXGIAdapter>,
            D3D_DRIVER_TYPE_HARDWARE,
            None,
            D3D11_CREATE_DEVICE_FLAG(0),
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut ctx_opt),
        ).context("D3D11CreateDevice")?;
        let device = device.ok_or_else(|| anyhow::anyhow!("D3D11CreateDevice: no device"))?;
        let ctx    = ctx_opt.ok_or_else(|| anyhow::anyhow!("D3D11CreateDevice: no context"))?;

        // ── 2. DXGI device → adapter → select output (monitor) ───────────────
        let dxgi_dev: IDXGIDevice = device.cast().context("cast IDXGIDevice")?;
        let adapter: IDXGIAdapter = dxgi_dev.GetParent().context("GetParent IDXGIAdapter")?;

        let monitor_idx = if monitor < 0 { 0u32 } else { monitor as u32 };
        let output: IDXGIOutput = adapter.EnumOutputs(monitor_idx)
            .with_context(|| format!("EnumOutputs({}): no output — device may not be in interactive session", monitor_idx))?;
        let desc = output.GetDesc().context("IDXGIOutput::GetDesc")?;
        let r = desc.DesktopCoordinates;
        let w = (r.right - r.left).unsigned_abs();
        let h = (r.bottom - r.top).unsigned_abs();
        if w == 0 || h == 0 { anyhow::bail!("Output {} has zero size {}x{}", monitor_idx, w, h); }

        // ── 3. Duplicate output ───────────────────────────────────────────────
        let output1: IDXGIOutput1 = output.cast().context("cast IDXGIOutput1")?;
        let dupl = output1.DuplicateOutput(&device).context("DuplicateOutput")?;

        // ── 4. Create CPU-readable staging texture ────────────────────────────
        let staging_desc = D3D11_TEXTURE2D_DESC {
            Width:     w,
            Height:    h,
            MipLevels: 1,
            ArraySize: 1,
            Format:    DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            Usage:     D3D11_USAGE_STAGING,
            BindFlags: 0u32,            // no bind flags
            CPUAccessFlags: 0x20000u32, // D3D11_CPU_ACCESS_READ
            MiscFlags: 0u32,
        };
        let mut staging_out: Option<ID3D11Texture2D> = None;
        device.CreateTexture2D(&staging_desc, None::<*const D3D11_SUBRESOURCE_DATA>, Some(&mut staging_out))
            .context("CreateTexture2D staging")?;
        let staging = staging_out.ok_or_else(|| anyhow::anyhow!("CreateTexture2D returned None"))?;
        let staging_res: ID3D11Resource = staging.cast().context("staging → ID3D11Resource")?;

        info!(backend = "dxgi-direct", monitor = monitor_idx, width = w, height = h, fps, quality, scale, "RD stream started");

        let frame_timeout_ms = (1000 / fps.max(1)) * 2;
        let frame_delay = Duration::from_millis((1000u64 / fps.max(1) as u64).saturating_sub(5));
        let mut seq: u64 = 1;

        loop {
            if stop_flag.load(Ordering::Relaxed) { break; }

            // ── 5. Acquire next frame ─────────────────────────────────────────
            let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut resource: Option<IDXGIResource> = None;

            match dupl.AcquireNextFrame(frame_timeout_ms, &mut frame_info, &mut resource) {
                Err(ref e) if e.code().0 == DXGI_ERROR_WAIT_TIMEOUT => continue,
                Err(ref e) if e.code().0 == DXGI_ERROR_ACCESS_LOST
                           || e.code().0 == DXGI_ERROR_DEVICE_RESET => {
                    anyhow::bail!("DXGI output lost (display reconfigured): {e}");
                }
                Err(e) => anyhow::bail!("AcquireNextFrame: {e}"),
                Ok(()) => {}
            }

            let resource = match resource {
                Some(r) => r,
                None => { let _ = dupl.ReleaseFrame(); continue; }
            };

            // ── 6. Copy GPU texture → CPU staging ─────────────────────────────
            let tex: ID3D11Texture2D = resource.cast().context("cast IDXGIResource → ID3D11Texture2D")?;
            let tex_res: ID3D11Resource = tex.cast().context("cast ID3D11Texture2D → ID3D11Resource")?;
            ctx.CopyResource(&staging_res, &tex_res);
            let _ = dupl.ReleaseFrame();

            // ── 7. Map staging texture and read pixels ────────────────────────
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            ctx.Map(&staging_res, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .context("Map staging texture")?;

            let row_pitch = mapped.RowPitch as usize;
            let data = std::slice::from_raw_parts(
                mapped.pData as *const u8,
                row_pitch * h as usize,
            );

            // BGRA → RGB
            let mut rgb = Vec::with_capacity(w as usize * h as usize * 3);
            for y in 0..h as usize {
                let row_start = y * row_pitch;
                let row = &data[row_start..row_start + w as usize * 4];
                for px in row.chunks_exact(4) {
                    rgb.push(px[2]); // R
                    rgb.push(px[1]); // G
                    rgb.push(px[0]); // B
                }
            }
            ctx.Unmap(&staging_res, 0);

            // ── 8. Encode JPEG and send ───────────────────────────────────────
            let jpeg = encode_jpeg_rgb(&rgb, w, h, quality, scale).context("encode_jpeg_rgb")?;
            let b64  = B64.encode(jpeg);
            if ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
                session_id: session_id.to_string(),
                stream_type: "frame".into(),
                data: b64,
                sequence: seq,
            })).is_err() { break; }
            seq = seq.wrapping_add(1);
            std::thread::sleep(frame_delay);
        }
    }

    info!(backend = "dxgi-direct", "RD stream stopped");
    Ok(())
}

/// Bind the current thread to the interactive desktop (WinSta0\Default).
/// This is required for GDI screen capture and DXGI enumeration when the process
/// was launched without an interactive window station (service / scheduled task context).
#[cfg(windows)]
fn bind_to_interactive_desktop() {
    use windows::Win32::System::StationsAndDesktops::{
        OpenDesktopW, OpenInputDesktop, OpenWindowStationW, SetProcessWindowStation, SetThreadDesktop,
        DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS,
    };
    unsafe {
        if let Ok(hws) = OpenWindowStationW(windows::core::w!("WinSta0"), false, 0x10000000u32) {
            let _ = SetProcessWindowStation(hws);
        }
        if let Ok(hd) = OpenInputDesktop(
            DESKTOP_CONTROL_FLAGS(0),
            false,
            DESKTOP_ACCESS_FLAGS(0x10000000u32),
        ) {
            let _ = SetThreadDesktop(hd);
        } else if let Ok(hd) = OpenDesktopW(
            windows::core::w!("Default"),
            DESKTOP_CONTROL_FLAGS(0),
            false,
            0x10000000u32,
        ) {
            let _ = SetThreadDesktop(hd);
        }
    }
}

#[cfg(windows)]
fn gdi_stream_loop_blocking(
    session_id: &str,
    monitor: i32,
    fps: u32,
    quality: u8,
    scale: f32,
    ws_tx: mpsc::Sender<AgentMessage>,
    stop_flag: Arc<AtomicBool>,
) -> Result<()> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC, GetDIBits,
        ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HBITMAP, HDC, RGBQUAD, ROP_CODE, SRCCOPY,
    };
    use windows::Win32::Graphics::Dwm::DwmFlush;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    };
    // Note: desktop binding already done via bind_to_interactive_desktop() in stream_loop_blocking.

    #[derive(Clone, Copy)]
    struct Rect { x: i32, y: i32, w: i32, h: i32 }

    fn pick_rect(monitor: i32) -> Rect {
        if let Ok(monitors) = list_monitors_windows() {
            if !monitors.is_empty() {
                let idx = if monitor >= 0 && (monitor as usize) < monitors.len() {
                    monitor as usize
                } else {
                    monitors.iter().position(|m| m.primary).unwrap_or(0)
                };
                let m = &monitors[idx];
                return Rect { x: m.x, y: m.y, w: m.width, h: m.height };
            }
        }

        unsafe {
            let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
            let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
            let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1);
            let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1);
            Rect { x: vx, y: vy, w: vw, h: vh }
        }
    }

    let rect = pick_rect(monitor);
    let w = rect.w.max(1);
    let h = rect.h.max(1);

    info!(backend = "gdi", x = rect.x, y = rect.y, width = w, height = h, fps = fps, quality = quality, scale = scale, "RD stream started");

    unsafe {
        let null_hwnd = HWND(std::ptr::null_mut());

        // Screen DC – bind_to_interactive_desktop() was already called by stream_loop_blocking.
        // GetDC(NULL) now gives the desktop DC of the interactive session.
        let screen_dc: HDC = GetDC(null_hwnd);
        let release_hwnd = null_hwnd;
        if screen_dc.0.is_null() {
            anyhow::bail!("GetDC failed: desktop not accessible");
        }

        let mem_dc: HDC = CreateCompatibleDC(screen_dc);
        if mem_dc.0.is_null() {
            let _ = ReleaseDC(release_hwnd, screen_dc);
            anyhow::bail!("CreateCompatibleDC failed");
        }

        let bmp: HBITMAP = CreateCompatibleBitmap(screen_dc, w, h);
        if bmp.0.is_null() {
            let _ = DeleteDC(mem_dc);
            let _ = ReleaseDC(release_hwnd, screen_dc);
            anyhow::bail!("CreateCompatibleBitmap failed");
        }

        let old = SelectObject(mem_dc, bmp);

        let frame_delay = Duration::from_millis((1000 / fps.max(1)) as u64);
        let mut seq: u64 = 0;
        let mut bgra = vec![0u8; (w as usize) * (h as usize) * 4];

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h, // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0 as u32,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [RGBQUAD { rgbBlue: 0, rgbGreen: 0, rgbRed: 0, rgbReserved: 0 }; 1],
        };

        let rop = ROP_CODE(SRCCOPY.0 | 0x40000000); // CAPTUREBLT (captures layered/transparent windows)

        while !stop_flag.load(Ordering::Relaxed) {
            // DwmFlush synchronises with the DWM compositor so BitBlt captures the
            // fully-composited frame rather than a stale/black buffer.
            let _ = DwmFlush();

            if let Err(e) = BitBlt(mem_dc, 0, 0, w, h, screen_dc, rect.x, rect.y, rop) {
                let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
                    session_id: session_id.to_string(),
                    stream_type: "error".into(),
                    data: format!("gdi BitBlt failed: {e}"),
                    sequence: seq,
                }));
                break;
            }

            let lines = GetDIBits(
                mem_dc,
                bmp,
                0,
                h as u32,
                Some(bgra.as_mut_ptr() as *mut _),
                &mut bmi,
                DIB_RGB_COLORS,
            );
            if lines == 0 {
                let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
                    session_id: session_id.to_string(),
                    stream_type: "error".into(),
                    data: "gdi GetDIBits failed".into(),
                    sequence: seq,
                }));
                break;
            }

            let mut rgb = Vec::with_capacity((w as usize) * (h as usize) * 3);
            for px in bgra.chunks_exact(4) {
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

        let _ = SelectObject(mem_dc, old);
        let _ = DeleteObject(bmp);
        let _ = DeleteDC(mem_dc);
        let _ = ReleaseDC(release_hwnd, screen_dc);
    }

    info!(backend = "gdi", "RD stream stopped");
    Ok(())
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
                    // MOUSEEVENTF_VIRTUALDESK maps (0,65535) to the full virtual screen
                    // spanning all monitors — required for correct positioning on multi-monitor setups.
                    dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
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
