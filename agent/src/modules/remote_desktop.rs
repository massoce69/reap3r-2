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
        let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
            session_id: session_id.to_string(),
            stream_type: "error".into(),
            data: "remote_desktop unsupported on this platform".into(),
            sequence: 0,
        }));
        return Ok(());
    }

    #[cfg(windows)]
    {
        // ── Bind to interactive desktop FIRST ─────────────────────────────────
        // Required so D3D11/DXGI can enumerate and duplicate the interactive output.
        bind_to_interactive_desktop();

        let own_pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
        info!(pid = own_pid, monitor, "RD stream starting");
        let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
            session_id: session_id.to_string(),
            stream_type: "debug".into(),
            data: format!("capture start: pid={own_pid} monitor={monitor}; trying DXGI OutputDuplication"),
            sequence: 0,
        }));

        // ── Strategy 1: direct DXGI OutputDuplication (correct for Win10/11 DWM) ──
        // Enumerates ALL adapters/outputs so it works on multi-GPU laptops too.
        // Requires D3D11_CREATE_DEVICE_BGRA_SUPPORT + D3D_DRIVER_TYPE_UNKNOWN + explicit adapter.
        match dxgi_direct_stream_loop_blocking(session_id, monitor, fps, quality, scale, &ws_tx, &stop_flag) {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!(error = %e, "DXGI OutputDuplication failed; falling back to GDI");
                let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
                    session_id: session_id.to_string(),
                    stream_type: "debug".into(),
                    data: format!("DXGI failed: {e}; falling back to GDI (may be black on Win10/11)"),
                    sequence: 0,
                }));
            }
        }

        // ── Strategy 2: GDI BitBlt (session-0 / DXGI unavailable fallback) ───
        gdi_stream_loop_blocking(session_id, monitor, fps, quality, scale, ws_tx, stop_flag)
    }
}

/// Direct IDXGIOutputDuplication screen capture.
/// This is the correct API for Windows 10/11 where DWM composites in GPU memory.
/// Works from any session once the process token has access to the adapter.
#[cfg(windows)]
/// Direct IDXGIOutputDuplication screen capture — correct API for Win10/11 DWM.
///
/// Key differences from a naive implementation:
/// • Enumerates ALL DXGI adapters (fixes multi-GPU / iGPU+dGPU laptops)
/// • Creates the D3D11 device on the SAME adapter as the target output (required)
/// • Uses D3D_DRIVER_TYPE_UNKNOWN when the adapter is specified (required)
/// • Sets D3D11_CREATE_DEVICE_BGRA_SUPPORT (0x20) — mandatory for Desktop Duplication
/// • Handles DXGI_ERROR_ACCESS_LOST by restarting duplication automatically
/// • Detects and logs all-black frames
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
    use windows::core::Interface;
    use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
    use windows::Win32::Graphics::Direct3D11::{
        D3D11CreateDevice, D3D11_CREATE_DEVICE_FLAG,
        D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
        D3D11_SUBRESOURCE_DATA, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
        ID3D11Device, ID3D11DeviceContext, ID3D11Resource, ID3D11Texture2D,
    };
    use windows::Win32::Graphics::Dxgi::{
        CreateDXGIFactory1,
        IDXGIAdapter, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput, IDXGIOutput1, IDXGIResource,
        DXGI_OUTDUPL_FRAME_INFO,
    };
    use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};

    // ─── HRESULT constants ────────────────────────────────────────────────────
    const DXGI_ERROR_WAIT_TIMEOUT:          i32 = 0x887A0027u32 as i32;
    const DXGI_ERROR_ACCESS_LOST:           i32 = 0x887A0026u32 as i32;
    const DXGI_ERROR_NOT_CURRENTLY_AVAIL:   i32 = 0x887A0022u32 as i32;
    // D3D11_CREATE_DEVICE_BGRA_SUPPORT = 0x20 — mandatory for desktop duplication
    const BGRA_SUPPORT: u32 = 0x20;

    let target_output = if monitor < 0 { 0u32 } else { monitor as u32 };

    unsafe {
        // ── Create DXGI 1.1 factory ──────────────────────────────────────────
        let factory: IDXGIFactory1 = CreateDXGIFactory1().context("CreateDXGIFactory1")?;

        // ── Enumerate all adapters, all their outputs ─────────────────────────
        // We assign a flat "global output index" to match the monitor parameter
        // coming from the frontend (which uses EnumDisplayMonitors order).
        let mut global_out_idx: u32 = 0;

        'adapter_loop: for adapter_idx in 0u32..16 {
            let adapter: IDXGIAdapter1 = match factory.EnumAdapters1(adapter_idx) {
                Ok(a) => a,
                Err(_) => break, // no more adapters
            };

            for out_idx in 0u32..16 {
                let output: IDXGIOutput = match adapter.EnumOutputs(out_idx) {
                    Ok(o) => o,
                    Err(_) => break, // no more outputs on this adapter
                };

                if global_out_idx != target_output {
                    global_out_idx += 1;
                    continue;
                }

                // ── Found the right output; get its dimensions ────────────────
                let odesc = output.GetDesc().context("IDXGIOutput::GetDesc")?;
                let r = odesc.DesktopCoordinates;
                let w = (r.right  - r.left).unsigned_abs().max(1);
                let h = (r.bottom - r.top ).unsigned_abs().max(1);

                info!(adapter=adapter_idx, out=out_idx, global=global_out_idx, w, h,
                      "DXGI OutputDuplication: found target output");

                // ── Create D3D11 device on THIS adapter ───────────────────────
                // Rules:
                //   • pAdapter specified  → DriverType MUST be D3D_DRIVER_TYPE_UNKNOWN
                //   • BGRA_SUPPORT flag   → required for Desktop Duplication
                // Cast IDXGIAdapter1 → IDXGIAdapter (the base interface accepted by D3D11CreateDevice)
                let adapter_base: IDXGIAdapter = match adapter.cast() {
                    Ok(a) => a,
                    Err(e) => { warn!(adapter=adapter_idx, %e, "cast IDXGIAdapter1→IDXGIAdapter failed"); global_out_idx += 1; continue; }
                };
                let mut device_opt: Option<ID3D11Device> = None;
                let mut ctx_opt:    Option<ID3D11DeviceContext> = None;
                let hr = D3D11CreateDevice(
                    Some(&adapter_base),
                    D3D_DRIVER_TYPE_UNKNOWN,
                    None,
                    D3D11_CREATE_DEVICE_FLAG(BGRA_SUPPORT),
                    None,
                    D3D11_SDK_VERSION,
                    Some(&mut device_opt),
                    None,
                    Some(&mut ctx_opt),
                );
                if hr.is_err() {
                    let e = hr.unwrap_err();
                    warn!(adapter=adapter_idx, %e, "D3D11CreateDevice failed on adapter, trying next");
                    global_out_idx += 1;
                    continue;
                }
                let device = match device_opt { Some(d) => d, None => { global_out_idx+=1; continue; } };
                let ctx    = match ctx_opt    { Some(c) => c, None => { global_out_idx+=1; continue; } };                // ── Cast IDXGIOutput → IDXGIOutput1 for DuplicateOutput ───────
                let output1: IDXGIOutput1 = output.cast().context("cast IDXGIOutput → IDXGIOutput1")?;

                // Send diagnostic
                let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
                    session_id: session_id.to_string(),
                    stream_type: "debug".into(),
                    data: format!("DXGI: adapter={adapter_idx} output={out_idx} {w}x{h} fps={fps} qual={quality} scale={scale}"),
                    sequence: 0,
                }));

                // ── Outer loop: re-creates duplication after ACCESS_LOST ───────
                'dup_loop: loop {
                    if stop_flag.load(Ordering::Relaxed) { break 'adapter_loop; }

                    let dupl = match output1.DuplicateOutput(&device) {
                        Ok(d) => d,
                        Err(e) => {
                            let code = e.code().0;
                            let msg = if code == DXGI_ERROR_NOT_CURRENTLY_AVAIL {
                                format!("DuplicateOutput: DXGI_ERROR_NOT_CURRENTLY_AVAILABLE (process not in interactive session or another duplication exists): {e}")
                            } else {
                                format!("DuplicateOutput hr=0x{code:08X}: {e}")
                            };
                            warn!("{msg}");
                            let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
                                session_id: session_id.to_string(),
                                stream_type: "error".into(),
                                data: msg.clone(),
                                sequence: 0,
                            }));
                            anyhow::bail!("{msg}");
                        }
                    };

                    // ── Create CPU-readable staging texture ───────────────────
                    let staging_desc = D3D11_TEXTURE2D_DESC {
                        Width:     w,
                        Height:    h,
                        MipLevels: 1,
                        ArraySize: 1,
                        Format:    DXGI_FORMAT_B8G8R8A8_UNORM,
                        SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
                        Usage:      D3D11_USAGE_STAGING,
                        BindFlags:  0u32,
                        CPUAccessFlags: 0x20000u32, // D3D11_CPU_ACCESS_READ
                        MiscFlags:  0u32,
                    };
                    let mut tex_out: Option<ID3D11Texture2D> = None;
                    device.CreateTexture2D(
                        &staging_desc,
                        None::<*const D3D11_SUBRESOURCE_DATA>,
                        Some(&mut tex_out),
                    ).context("CreateTexture2D staging")?;
                    let staging     = tex_out.ok_or_else(|| anyhow::anyhow!("staging texture is None"))?;
                    let staging_res: ID3D11Resource = staging.cast().context("staging → ID3D11Resource")?;

                    info!(backend="dxgi-dupl", adapter=adapter_idx, out=out_idx, w, h,
                          fps, quality, scale, "RD stream started");

                    let frame_timeout_ms = (1000 / fps.max(1)) * 2;
                    let frame_delay = Duration::from_millis(
                        (1000u64 / fps.max(1) as u64).saturating_sub(2),
                    );
                    let mut seq: u64 = 1;
                    let mut black_streak: u32 = 0;

                    // ── Frame capture loop ────────────────────────────────────
                    'frame_loop: loop {
                        if stop_flag.load(Ordering::Relaxed) { break 'adapter_loop; }

                        let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
                        let mut resource_opt: Option<IDXGIResource> = None;

                        match dupl.AcquireNextFrame(
                            frame_timeout_ms,
                            &mut frame_info,
                            &mut resource_opt,
                        ) {
                            Err(ref e) if e.code().0 == DXGI_ERROR_WAIT_TIMEOUT => {
                                // No change on screen; re-try immediately (no sleep needed)
                                continue;
                            }
                            Err(ref e) if e.code().0 == DXGI_ERROR_ACCESS_LOST => {
                                warn!("DXGI_ERROR_ACCESS_LOST (display mode changed); re-creating duplication");
                                break 'frame_loop; // → 'dup_loop restarts
                            }
                            Err(e) => {
                                let _ = ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
                                    session_id: session_id.to_string(),
                                    stream_type: "error".into(),
                                    data: format!("AcquireNextFrame: {e}"),
                                    sequence: seq,
                                }));
                                anyhow::bail!("AcquireNextFrame: {e}");
                            }
                            Ok(()) => {}
                        }

                        let resource = match resource_opt {
                            Some(r) => r,
                            None    => { let _ = dupl.ReleaseFrame(); continue; }
                        };

                        // Copy GPU texture → CPU staging
                        let tex:     ID3D11Texture2D = resource.cast()
                            .context("cast IDXGIResource → ID3D11Texture2D")?;
                        let tex_res: ID3D11Resource  = tex.cast()
                            .context("cast ID3D11Texture2D → ID3D11Resource")?;
                        ctx.CopyResource(&staging_res, &tex_res);
                        let _ = dupl.ReleaseFrame();

                        // Map staging and read pixels
                        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                        if let Err(e) = ctx.Map(&staging_res, 0, D3D11_MAP_READ, 0, Some(&mut mapped)) {
                            warn!("Map failed: {e}"); continue;
                        }

                        let row_pitch = mapped.RowPitch as usize;
                        let total_bytes = row_pitch * h as usize;
                        let data = std::slice::from_raw_parts(
                            mapped.pData as *const u8,
                            total_bytes,
                        );

                        // Black-frame detection: sample first 64 bytes
                        let sample_end = total_bytes.min(64);
                        let is_black = data[..sample_end].iter().all(|&b| b == 0);
                        if is_black {
                            black_streak += 1;
                            if black_streak <= 5 || black_streak % 60 == 0 {
                                warn!(black_streak, "⚠ captured frame is all-black (session isolation? wrong adapter? DRM content?)");
                            }
                        } else {
                            black_streak = 0;
                        }

                        // BGRA → RGB conversion
                        let mut rgb = Vec::with_capacity(w as usize * h as usize * 3);
                        for y in 0..h as usize {
                            let row = &data[y * row_pitch .. y * row_pitch + w as usize * 4];
                            for px in row.chunks_exact(4) {
                                rgb.push(px[2]); // R (BGRA: B=0,G=1,R=2,A=3)
                                rgb.push(px[1]); // G
                                rgb.push(px[0]); // B
                            }
                        }
                        ctx.Unmap(&staging_res, 0);

                        // Encode and send
                        let jpeg = encode_jpeg_rgb(&rgb, w, h, quality, scale)
                            .context("encode_jpeg_rgb")?;
                        let b64 = B64.encode(jpeg);
                        if ws_tx.blocking_send(AgentMessage::StreamOutput(StreamOutputPayload {
                            session_id: session_id.to_string(),
                            stream_type: "frame".into(),
                            data: b64,
                            sequence: seq,
                        })).is_err() {
                            break 'adapter_loop; // receiver dropped
                        }
                        seq = seq.wrapping_add(1);
                        std::thread::sleep(frame_delay);
                    } // 'frame_loop

                    // Brief pause before re-creating duplication (ACCESS_LOST recovery)
                    std::thread::sleep(Duration::from_millis(400));
                } // 'dup_loop

                info!(backend="dxgi-dupl", "RD stream stopped");
                return Ok(());
            } // output loop
        } // adapter loop
    } // unsafe

    Err(anyhow::anyhow!(
        "DXGI: no usable output found for monitor index {target_output} \
         (tried all adapters; process may be in Session 0 where Desktop Duplication is unavailable)"
    ))
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
