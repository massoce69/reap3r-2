'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, StatusDot, Skeleton, Input } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { realtime } from '@/lib/ws';
import { formatDate, statusColor } from '@/lib/utils';
import { RolePermissions, Permission, JobType } from '@massvision/shared';
import {
  Monitor, Terminal, Play, RotateCcw, Power, PowerOff,
  Shield, Cpu, HardDrive, Network, Clock, ArrowLeft, Trash2,
  Package, Activity, RefreshCw, ChevronDown, ChevronRight,
  Server, MemoryStick, Wifi, Layers, Loader2, Square,
  Send, AlertCircle, CheckCircle, XCircle, Copy, Check,
  ScreenShare, Maximize2, Minimize2, Camera, MousePointer,
  FolderOpen, Folder, File, FileText, Upload, Download, ArrowUp, Home,
} from 'lucide-react';

type Tab = 'overview' | 'terminal' | 'remote-desktop' | 'file-explorer' | 'inventory' | 'metrics' | 'jobs';

interface FileEntry {
  name: string;
  type: 'file' | 'directory';
  size: number;
  modified: string;
  permissions?: string;
}

export default function AgentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { user } = useAuth();
  const [agent, setAgent] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>('overview');
  const [scriptOpen, setScriptOpen] = useState(false);
  const [script, setScript] = useState('');
  const [interpreter, setInterpreter] = useState<'bash' | 'powershell' | 'python'>('bash');
  const [submitting, setSubmitting] = useState(false);
  const [recentJobs, setRecentJobs] = useState<any[]>([]);
  const [inventory, setInventory] = useState<any>(null);
  const [metricsData, setMetricsData] = useState<any[]>([]);
  const [metricsPeriod, setMetricsPeriod] = useState(24);

  // Terminal state
  const [termCmd, setTermCmd] = useState('');
  const [termInterpreter, setTermInterpreter] = useState<'powershell' | 'bash' | 'cmd' | 'python'>('powershell');
  const [termHistory, setTermHistory] = useState<Array<{
    id: string; cmd: string; status: 'pending' | 'running' | 'completed' | 'failed' | 'dispatched';
    stdout?: string; stderr?: string; exit_code?: number; duration_ms?: number; created_at: string;
  }>>([]);
  const [termRunning, setTermRunning] = useState(false);
  const termEndRef = useRef<HTMLDivElement>(null);
  const termInputRef = useRef<HTMLInputElement>(null);
  // Script execution result
  const [lastScriptResult, setLastScriptResult] = useState<any>(null);

  // Remote desktop state
  const [rdFrame, setRdFrame] = useState<string | null>(null);
  const [rdLoading, setRdLoading] = useState(false);
  const [rdStreaming, setRdStreaming] = useState(false);
  const [rdQuality, setRdQuality] = useState(50);
  const [rdScale, setRdScale] = useState(50);
  const [rdFps, setRdFps] = useState(2);
  const [rdError, setRdError] = useState<string | null>(null);
  const [rdFullscreen, setRdFullscreen] = useState(false);
  const [rdFrameCount, setRdFrameCount] = useState(0);
  const [rdSessionId, setRdSessionId] = useState<string | null>(null);
  const rdContainerRef = useRef<HTMLDivElement>(null);
  // Multi-monitor state
  const [rdMonitors, setRdMonitors] = useState<Array<{ index: number; name: string; primary: boolean; x: number; y: number; width: number; height: number }>>([]);
  const [rdSelectedMonitor, setRdSelectedMonitor] = useState<number>(-1); // -1 = all screens
  const [rdMonitorsLoading, setRdMonitorsLoading] = useState(false);

  // File explorer state
  const [fePath, setFePath] = useState(agent?.os === 'windows' ? 'C:\\' : '/');
  const [feFiles, setFeFiles] = useState<FileEntry[]>([]);
  const [feLoading, setFeLoading] = useState(false);
  const [feError, setFeError] = useState<string | null>(null);
  const [feHistory, setFeHistory] = useState<string[]>([]);
  const [feUploading, setFeUploading] = useState(false);
  const [feDownloading, setFeDownloading] = useState<string | null>(null);
  const [fePathInput, setFePathInput] = useState('');
  const feUploadRef = useRef<HTMLInputElement>(null);

  const userPerms = user ? RolePermissions[user.role as keyof typeof RolePermissions] ?? [] : [];
  const canRunScript = userPerms.includes(Permission.JobRunScript);
  const canReboot = userPerms.includes(Permission.JobReboot);
  const canDelete = userPerms.includes(Permission.AgentDelete);

  const refresh = useCallback(() => {
    if (!id) return;
    Promise.all([
      api.agents.get(id),
      api.jobs.list({ agent_id: id, limit: '10', sort_order: 'desc' }),
    ]).then(([agentData, jobsData]) => {
      setAgent(agentData);
      setRecentJobs(jobsData.data);
      setLoading(false);
    }).catch(() => {
      setLoading(false);
      router.push('/agents');
    });
  }, [id]);

  useEffect(() => { refresh(); }, [refresh]);

  // Load inventory when tab switches
  useEffect(() => {
    if (tab === 'inventory' && id && !inventory) {
      api.agents.inventory(id).then(setInventory).catch(() => {});
    }
  }, [tab, id]);

  // Load metrics when tab switches
  useEffect(() => {
    if (tab === 'metrics' && id) {
      api.agents.metrics(id, metricsPeriod).then(r => setMetricsData(r.data)).catch(() => {});
    }
  }, [tab, id, metricsPeriod]);

  const isOnline = agent?.status === 'online';
  const hasCapability = (cap: string) => {
    const caps = agent?.capabilities;
    if (Array.isArray(caps)) return caps.includes(cap);
    if (caps?.modules) return caps.modules.includes(cap);
    return false;
  };

  const pollJobResult = async (jobId: string, historyIdx: number) => {
    let attempts = 0;
    const maxAttempts = 150; // 5 min at 2s interval
    const poll = async () => {
      if (attempts >= maxAttempts) {
        setTermHistory(prev => prev.map((h, i) => i === historyIdx ? { ...h, status: 'failed' as const, stderr: 'Timeout: no result after 5 minutes' } : h));
        setTermRunning(false);
        return;
      }
      attempts++;
      try {
        const job = await api.jobs.get(jobId);
        if (job.status === 'completed' || job.status === 'failed') {
          setTermHistory(prev => prev.map((h, i) => i === historyIdx ? {
            ...h,
            status: job.status as 'completed' | 'failed',
            stdout: job.result?.stdout ?? job.stdout ?? '',
            stderr: job.result?.stderr ?? job.stderr ?? '',
            exit_code: job.result?.exit_code ?? job.exit_code,
            duration_ms: job.result?.duration_ms ?? job.duration_ms,
          } : h));
          setTermRunning(false);
          return;
        }
        if (job.status === 'running' || job.status === 'dispatched') {
          setTermHistory(prev => prev.map((h, i) => i === historyIdx ? { ...h, status: job.status as 'running' | 'dispatched' } : h));
        }
      } catch { /* ignore network errors during polling */ }
      setTimeout(poll, 2000);
    };
    setTimeout(poll, 1500);
  };

  const runTerminalCommand = async (cmd?: string) => {
    const command = cmd ?? termCmd;
    if (!agent || !command.trim() || termRunning) return;
    setTermRunning(true);
    const entry = {
      id: '', cmd: command, status: 'pending' as const, created_at: new Date().toISOString(),
    };
    const idx = termHistory.length;
    setTermHistory(prev => [...prev, entry]);
    setTermCmd('');
    try {
      const job = await api.jobs.create({
        agent_id: agent.id,
        type: JobType.RunScript,
        payload: { interpreter: termInterpreter, script: command, timeout_secs: 300, stream_output: false },
        reason: `Terminal: ${command.substring(0, 80)}`,
      });
      const jobId = job.id ?? job.job_id;
      setTermHistory(prev => prev.map((h, i) => i === idx ? { ...h, id: jobId, status: 'pending' } : h));
      pollJobResult(jobId, idx);
    } catch (err: any) {
      setTermHistory(prev => prev.map((h, i) => i === idx ? { ...h, status: 'failed', stderr: err?.message ?? 'Failed to create job' } : h));
      setTermRunning(false);
    }
  };

  const runScript = async () => {
    if (!agent || !script.trim()) return;
    setSubmitting(true);
    try {
      const job = await api.jobs.create({
        agent_id: agent.id,
        type: JobType.RunScript,
        payload: { interpreter, script, timeout_secs: 300, stream_output: false },
        reason: 'Manual script execution from UI',
      });
      setScriptOpen(false);
      setScript('');
      setLastScriptResult(null);
      // Also add to terminal history for visibility
      const jobId = job.id ?? job.job_id;
      const idx = termHistory.length;
      setTermHistory(prev => [...prev, {
        id: jobId, cmd: `[Script] ${script.substring(0, 100)}...`, status: 'pending' as const,
        created_at: new Date().toISOString(),
      }]);
      pollJobResult(jobId, idx);
      const jobsData = await api.jobs.list({ agent_id: agent.id, limit: '10', sort_order: 'desc' });
      setRecentJobs(jobsData.data);
    } finally {
      setSubmitting(false);
    }
  };

  const sendAction = async (type: JobType, payload: Record<string, unknown>, reason: string) => {
    if (!agent) return;
    await api.jobs.create({ agent_id: agent.id, type, payload, reason });
    const jobsData = await api.jobs.list({ agent_id: agent.id, limit: '10', sort_order: 'desc' });
    setRecentJobs(jobsData.data);
  };

  // Auto-scroll terminal
  useEffect(() => {
    termEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [termHistory]);

  // ── Remote Desktop: fetch available monitors ──
  const fetchMonitors = async () => {
    if (!agent || rdMonitorsLoading) return;
    console.log('[RD] Fetching monitors for agent:', agent.id);
    setRdMonitorsLoading(true);
    try {
      const job = await api.jobs.create({
        agent_id: agent.id,
        type: JobType.ListMonitors,
        payload: {},
        reason: 'List monitors',
      });
      const jobId = job.id ?? job.job_id;
      // Poll for result (max 10 seconds)
      let attempts = 0;
      const poll = async (): Promise<void> => {
        if (attempts >= 20) {
          console.warn('[RD] Monitor list timeout');
          setRdMonitorsLoading(false);
          return;
        }
        attempts++;
        try {
          const j = await api.jobs.get(jobId);
          if (j.status === 'completed' || j.status === 'success') {
            const stdout = j.result?.stdout ?? j.stdout ?? '';
            try {
              const parsed = JSON.parse(stdout);
              const monitors = Array.isArray(parsed) ? parsed : [parsed];
              console.log('[RD] Monitors found:', monitors);
              setRdMonitors(monitors);
              // If only 1 monitor, auto-select it
              if (monitors.length === 1) {
                setRdSelectedMonitor(0);
              }
            } catch {
              console.warn('[RD] Failed to parse monitors JSON:', stdout);
            }
            setRdMonitorsLoading(false);
            return;
          }
          if (j.status === 'failed') {
            console.warn('[RD] Monitor list job failed');
            setRdMonitorsLoading(false);
            return;
          }
        } catch { /* retry */ }
        await new Promise(r => setTimeout(r, 500));
        return poll();
      };
      await poll();
    } catch (err: any) {
      console.error('[RD] Failed to fetch monitors:', err);
      setRdMonitorsLoading(false);
    }
  };

  // Auto-fetch monitors when switching to RD tab
  useEffect(() => {
    if (tab === 'remote-desktop' && agent && isOnline && rdMonitors.length === 0 && !rdMonitorsLoading) {
      fetchMonitors();
    }
  }, [tab, agent?.id, isOnline]);

  // ── Remote Desktop: WebSocket video streaming ──
  const startRdStream = async () => {
    if (!agent || rdLoading) return;
    console.log('[RD] Starting stream, agent:', agent.id, 'monitor:', rdSelectedMonitor, 'ws connected:', realtime.connected);
    setRdLoading(true);
    setRdError(null);
    setRdFrameCount(0);
    try {
      const job = await api.jobs.create({
        agent_id: agent.id,
        type: JobType.RemoteDesktopStart,
        payload: { mode: 'view', fps: rdFps, quality: rdQuality, codec: 'jpeg', scale: rdScale / 100, monitor: rdSelectedMonitor },
        reason: 'Remote Desktop stream',
      });
      const jobId = job.id ?? job.job_id;
      console.log('[RD] Job created:', jobId);
      setRdSessionId(jobId);
      setRdStreaming(true);
      setRdLoading(false);
    } catch (err: any) {
      console.error('[RD] Failed to start:', err);
      setRdError(err?.message ?? 'Failed to start remote desktop');
      setRdLoading(false);
    }
  };

  const stopRdStream = async () => {
    if (!agent) return;
    console.log('[RD] Stopping stream');
    setRdStreaming(false);
    setRdSessionId(null);
    setRdFrame(null);
    try {
      await api.jobs.create({
        agent_id: agent.id,
        type: JobType.RemoteDesktopStop,
        payload: {},
        reason: 'Stop remote desktop',
      });
    } catch { /* best effort */ }
  };

  // Subscribe to rd:frame WebSocket events
  useEffect(() => {
    if (!rdStreaming || !agent) return;
    console.log('[RD] Subscribing to rd:frame events for agent:', agent.id, 'ws connected:', realtime.connected);
    let frameRx = 0;
    const unsub = realtime.on('rd:frame', (msg: any) => {
      const p = msg.payload ?? msg;
      frameRx++;
      if (frameRx <= 3 || frameRx % 30 === 0) {
        console.log(`[RD] Frame received #${frameRx}, agent_id=${p.agent_id}, match=${p.agent_id === agent.id}, dataLen=${p.data?.length || 0}`);
      }
      if (p.agent_id === agent.id) {
        setRdFrame(`data:image/jpeg;base64,${p.data}`);
        setRdFrameCount(prev => prev + 1);
      }
    });
    return () => { console.log('[RD] Unsubscribing from rd:frame'); unsub(); };
  }, [rdStreaming, agent?.id]);

  // Stop stream when leaving tab
  useEffect(() => {
    if (tab !== 'remote-desktop' && rdStreaming) {
      stopRdStream();
    }
  }, [tab]);

  // Auto-restart stream when settings change mid-stream
  const rdSettingsRef = useRef({ quality: rdQuality, scale: rdScale, fps: rdFps, monitor: rdSelectedMonitor });
  useEffect(() => {
    const prev = rdSettingsRef.current;
    const changed = prev.quality !== rdQuality || prev.scale !== rdScale || prev.fps !== rdFps || prev.monitor !== rdSelectedMonitor;
    rdSettingsRef.current = { quality: rdQuality, scale: rdScale, fps: rdFps, monitor: rdSelectedMonitor };
    if (changed && rdStreaming && !rdLoading && agent) {
      console.log('[RD] Settings changed mid-stream, restarting with new params');
      // Stop then restart with new settings
      (async () => {
        await stopRdStream();
        // Small delay to let the stop propagate
        await new Promise(r => setTimeout(r, 500));
        startRdStream();
      })();
    }
  }, [rdQuality, rdScale, rdFps, rdSelectedMonitor]);

  // Also keep the single screenshot capture as fallback
  const captureScreenshot = async () => {
    if (!agent || rdLoading) return;
    setRdLoading(true);
    setRdError(null);
    try {
      // Build screen bounds selection based on monitor choice
      const monIdx = rdSelectedMonitor;
      const boundsCode = monIdx >= 0
        ? `$screens=[System.Windows.Forms.Screen]::AllScreens; if(${monIdx} -lt $screens.Length){$s=$screens[${monIdx}].Bounds}else{$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds}`
        : `$minX=[int]::MaxValue;$minY=[int]::MaxValue;$maxX=[int]::MinValue;$maxY=[int]::MinValue;foreach($scr in [System.Windows.Forms.Screen]::AllScreens){$b=$scr.Bounds;if($b.X -lt $minX){$minX=$b.X};if($b.Y -lt $minY){$minY=$b.Y};if(($b.X+$b.Width) -gt $maxX){$maxX=$b.X+$b.Width};if(($b.Y+$b.Height) -gt $maxY){$maxY=$b.Y+$b.Height}};$s=New-Object System.Drawing.Rectangle($minX,$minY,($maxX-$minX),($maxY-$minY))`;
      const SCREENSHOT_SCRIPT = `Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; ${boundsCode}; $w=[int][Math]::Round($s.Width*${rdScale/100}); $h=[int][Math]::Round($s.Height*${rdScale/100}); $bmp=New-Object System.Drawing.Bitmap($s.Width,$s.Height); $g=[System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($s.Location,[System.Drawing.Point]::Empty,$s.Size); $resized=New-Object System.Drawing.Bitmap($w,$h); $g2=[System.Drawing.Graphics]::FromImage($resized); $g2.InterpolationMode=[System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic; $g2.DrawImage($bmp,0,0,$w,$h); $ms=New-Object System.IO.MemoryStream; $enc=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|Where-Object{$_.MimeType -eq 'image/jpeg'}; $ep=New-Object System.Drawing.Imaging.EncoderParameters(1); $ep.Param[0]=New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality,[long]${rdQuality}); $resized.Save($ms,$enc,$ep); [Convert]::ToBase64String($ms.ToArray()); $g.Dispose(); $g2.Dispose(); $bmp.Dispose(); $resized.Dispose(); $ms.Dispose()`;
      const job = await api.jobs.create({
        agent_id: agent.id,
        type: JobType.RunScript,
        payload: { interpreter: 'powershell', script: SCREENSHOT_SCRIPT, timeout_secs: 30, stream_output: false },
        reason: 'Remote Desktop screenshot',
      });
      const jobId = job.id ?? job.job_id;
      let attempts = 0;
      const poll = async () => {
        if (attempts >= 30) { setRdError('Screenshot timeout'); setRdLoading(false); return; }
        attempts++;
        try {
          const j = await api.jobs.get(jobId);
          if (j.status === 'completed') {
            const b64 = j.result?.stdout ?? j.stdout ?? '';
            if (b64 && b64.length > 100) { setRdFrame(`data:image/jpeg;base64,${b64.trim()}`); setRdError(null); }
            else { setRdError('Empty screenshot data'); }
            setRdLoading(false); return;
          }
          if (j.status === 'failed') { setRdError(j.result?.stderr ?? j.stderr ?? 'Screenshot failed'); setRdLoading(false); return; }
        } catch { /* retry */ }
        setTimeout(poll, 2000);
      };
      setTimeout(poll, 1500);
    } catch (err: any) { setRdError(err?.message ?? 'Failed to capture screenshot'); setRdLoading(false); }
  };

  const collectInventoryNow = async () => {
    if (!id) return;
    try {
      await api.agents.collectInventory(id);
      setTimeout(() => {
        api.agents.inventory(id).then(setInventory).catch(() => {});
      }, 5000);
    } catch {}
  };

  const deleteAgent = async () => {
    if (!agent || !confirm('Are you sure you want to delete this agent?')) return;
    await api.agents.delete(agent.id);
    router.push('/agents');
  };

  // ── File Explorer: helpers ──
  const isWindows = agent?.os === 'windows';

  const feListDir = async (dirPath: string) => {
    if (!agent) return;
    setFeLoading(true);
    setFeError(null);
    try {
      const script = isWindows
        ? `Get-ChildItem -Path '${dirPath.replace(/'/g, "''")}' -Force -ErrorAction Stop | Select-Object Name,@{N='Type';E={if($_.PSIsContainer){'directory'}else{'file'}}},Length,LastWriteTime | ConvertTo-Json -Compress`
        : `ls -la --time-style=long-iso '${dirPath.replace(/'/g, "'\\''")}' 2>/dev/null | tail -n +2 | awk '{printf "{\\"name\\":\\"%s\\",\\"type\\":\\"%s\\",\\"size\\":%s,\\"modified\\":\\"%s %s\\",\\"permissions\\":\\"%s\\"}\\n", $NF, ($1 ~ /^d/ ? "directory" : "file"), ($5+0), $6, $7, $1}'`;
      const job = await api.jobs.create({
        agent_id: agent.id,
        type: JobType.RunScript,
        payload: { interpreter: isWindows ? 'powershell' : 'bash', script, timeout_sec: 15, stream_output: false },
        reason: `List directory: ${dirPath}`,
      });
      const jobId = job.id ?? job.job_id;
      let attempts = 0;
      const poll = async () => {
        if (attempts >= 20) { setFeError('Timeout listing directory'); setFeLoading(false); return; }
        attempts++;
        try {
          const j = await api.jobs.get(jobId);
          if (j.status === 'completed') {
            const raw = j.result?.stdout ?? j.stdout ?? '';
            try {
              let parsed = JSON.parse(raw);
              if (!Array.isArray(parsed)) parsed = [parsed];
              const entries: FileEntry[] = parsed.map((f: any) => ({
                name: f.Name ?? f.name ?? '',
                type: (f.Type ?? f.type ?? 'file').toLowerCase() === 'directory' ? 'directory' as const : 'file' as const,
                size: f.Length ?? f.size ?? 0,
                modified: f.LastWriteTime ?? f.modified ?? '',
                permissions: f.permissions,
              })).filter((f: FileEntry) => f.name);
              entries.sort((a: FileEntry, b: FileEntry) => {
                if (a.type !== b.type) return a.type === 'directory' ? -1 : 1;
                return a.name.localeCompare(b.name);
              });
              setFeFiles(entries);
              setFePath(dirPath);
              setFePathInput(dirPath);
              setFeLoading(false);
            } catch {
              setFeError('Failed to parse directory listing');
              setFeLoading(false);
            }
            return;
          }
          if (j.status === 'failed') {
            setFeError(j.result?.stderr ?? j.stderr ?? 'Failed to list directory');
            setFeLoading(false);
            return;
          }
        } catch { /* retry */ }
        setTimeout(poll, 1500);
      };
      setTimeout(poll, 1000);
    } catch (err: any) { setFeError(err?.message ?? 'Failed to list directory'); setFeLoading(false); }
  };

  const feNavigate = (name: string) => {
    const sep = isWindows ? '\\' : '/';
    const newPath = fePath.endsWith(sep) ? `${fePath}${name}` : `${fePath}${sep}${name}`;
    setFeHistory(prev => [...prev, fePath]);
    feListDir(newPath);
  };

  const feGoUp = () => {
    const sep = isWindows ? '\\' : '/';
    const parts = fePath.replace(/[/\\]$/, '').split(/[/\\]/);
    if (parts.length <= 1) return;
    parts.pop();
    let parent = parts.join(sep);
    if (isWindows && parent.length === 2 && parent[1] === ':') parent += sep;
    if (!isWindows && parent === '') parent = '/';
    setFeHistory(prev => [...prev, fePath]);
    feListDir(parent);
  };

  const feGoHome = () => {
    const home = isWindows ? 'C:\\' : '/';
    setFeHistory(prev => [...prev, fePath]);
    feListDir(home);
  };

  const feGoBack = () => {
    if (feHistory.length === 0) return;
    const prev = feHistory[feHistory.length - 1];
    setFeHistory(h => h.slice(0, -1));
    feListDir(prev);
  };

  const feDownload = async (fileName: string) => {
    if (!agent) return;
    setFeDownloading(fileName);
    try {
      const sep = isWindows ? '\\' : '/';
      const fullPath = fePath.endsWith(sep) ? `${fePath}${fileName}` : `${fePath}${sep}${fileName}`;
      const script = isWindows
        ? `[Convert]::ToBase64String([System.IO.File]::ReadAllBytes('${fullPath.replace(/'/g, "''")}'))`
        : `base64 '${fullPath.replace(/'/g, "'\\''")}'`;
      const job = await api.jobs.create({
        agent_id: agent.id,
        type: JobType.RunScript,
        payload: { interpreter: isWindows ? 'powershell' : 'bash', script, timeout_sec: 60, stream_output: false },
        reason: `Download file: ${fullPath}`,
      });
      const jobId = job.id ?? job.job_id;
      let attempts = 0;
      const poll = async () => {
        if (attempts >= 40) { setFeError('Download timeout'); setFeDownloading(null); return; }
        attempts++;
        try {
          const j = await api.jobs.get(jobId);
          if (j.status === 'completed') {
            const b64 = (j.result?.stdout ?? j.stdout ?? '').trim();
            if (b64.length > 0) {
              const byteChars = atob(b64);
              const byteArray = new Uint8Array(byteChars.length);
              for (let i = 0; i < byteChars.length; i++) byteArray[i] = byteChars.charCodeAt(i);
              const blob = new Blob([byteArray]);
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url; a.download = fileName; a.click();
              URL.revokeObjectURL(url);
            } else { setFeError('Empty file'); }
            setFeDownloading(null); return;
          }
          if (j.status === 'failed') { setFeError(j.result?.stderr ?? j.stderr ?? 'Download failed'); setFeDownloading(null); return; }
        } catch { /* retry */ }
        setTimeout(poll, 2000);
      };
      setTimeout(poll, 1500);
    } catch (err: any) { setFeError(err?.message ?? 'Failed to download'); setFeDownloading(null); }
  };

  const feUpload = async (file: globalThis.File) => {
    if (!agent) return;
    setFeUploading(true);
    setFeError(null);
    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let b64 = '';
      const CHUNK = 8192;
      for (let i = 0; i < bytes.length; i += CHUNK) {
        b64 += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
      }
      b64 = btoa(b64);
      const sep = isWindows ? '\\' : '/';
      const destPath = fePath.endsWith(sep) ? `${fePath}${file.name}` : `${fePath}${sep}${file.name}`;
      const script = isWindows
        ? `[System.IO.File]::WriteAllBytes('${destPath.replace(/'/g, "''")}', [Convert]::FromBase64String('${b64}')); Write-Output 'OK'`
        : `echo '${b64}' | base64 -d > '${destPath.replace(/'/g, "'\\''")}' && echo OK`;
      const job = await api.jobs.create({
        agent_id: agent.id,
        type: JobType.RunScript,
        payload: { interpreter: isWindows ? 'powershell' : 'bash', script, timeout_sec: 120, stream_output: false },
        reason: `Upload file: ${destPath}`,
      });
      const jobId = job.id ?? job.job_id;
      let attempts = 0;
      const poll = async () => {
        if (attempts >= 60) { setFeError('Upload timeout'); setFeUploading(false); return; }
        attempts++;
        try {
          const j = await api.jobs.get(jobId);
          if (j.status === 'completed') {
            setFeUploading(false);
            feListDir(fePath); // refresh listing
            return;
          }
          if (j.status === 'failed') { setFeError(j.result?.stderr ?? j.stderr ?? 'Upload failed'); setFeUploading(false); return; }
        } catch { /* retry */ }
        setTimeout(poll, 2000);
      };
      setTimeout(poll, 1500);
    } catch (err: any) { setFeError(err?.message ?? 'Failed to upload'); setFeUploading(false); }
  };

  // Load file explorer when switching to tab
  useEffect(() => {
    if (tab === 'file-explorer' && feFiles.length === 0 && !feLoading && agent) {
      const home = agent.os === 'windows' ? 'C:\\' : '/';
      setFePath(home);
      setFePathInput(home);
      feListDir(home);
    }
  }, [tab, agent?.id]);

  if (loading) {
    return (
      <>
        <TopBar title="Agent Details" />
        <div className="p-6 space-y-4">
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      </>
    );
  }

  if (!agent) return null;

  const tabs: { key: Tab; label: string; icon: React.ReactNode }[] = [
    { key: 'overview', label: 'Overview', icon: <Monitor className="w-4 h-4" /> },
    { key: 'terminal', label: 'Terminal', icon: <Terminal className="w-4 h-4" /> },
    { key: 'remote-desktop', label: 'Remote Desktop', icon: <ScreenShare className="w-4 h-4" /> },
    { key: 'file-explorer', label: 'Files', icon: <FolderOpen className="w-4 h-4" /> },
    { key: 'inventory', label: 'Inventory', icon: <Package className="w-4 h-4" /> },
    { key: 'metrics', label: 'Metrics', icon: <Activity className="w-4 h-4" /> },
    { key: 'jobs', label: 'Jobs', icon: <Layers className="w-4 h-4" /> },
  ];

  return (
    <>
      <TopBar
        title={agent.hostname}
        actions={
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={() => router.push('/agents')}>
              <ArrowLeft className="w-4 h-4" /> Back
            </Button>
            <Button variant="ghost" size="sm" onClick={refresh}>
              <RefreshCw className="w-4 h-4" />
            </Button>
            {canDelete && (
              <Button variant="danger" size="sm" onClick={deleteAgent}>
                <Trash2 className="w-4 h-4" /> Delete
              </Button>
            )}
          </div>
        }
      />
      <div className="p-6 space-y-6">
        {/* Agent Header */}
        <Card>
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-reap3r-accent/10 flex items-center justify-center">
                <Monitor className="w-6 h-6 text-reap3r-accent" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-reap3r-text">{agent.hostname}</h3>
                <div className="flex items-center gap-2 mt-1">
                  <StatusDot status={agent.status} />
                  <span className={`text-sm capitalize ${statusColor(agent.status)}`}>{agent.status}</span>
                  {agent.isolated && <Badge variant="danger">ISOLATED</Badge>}
                </div>
              </div>
            </div>
            <div className="flex gap-2 items-center">
              <Badge variant={isOnline ? 'success' : 'default'}>{agent.agent_version}</Badge>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-4">
            <InfoItem icon={<Cpu className="w-4 h-4" />} label="OS" value={`${agent.os} ${agent.os_version ?? ''}`} />
            <InfoItem icon={<HardDrive className="w-4 h-4" />} label="Arch" value={agent.arch} />
            <InfoItem icon={<Network className="w-4 h-4" />} label="IP" value={agent.ip_address ?? agent.last_ip ?? '—'} />
            <InfoItem icon={<Clock className="w-4 h-4" />} label="Last Seen" value={formatDate(agent.last_seen_at)} />
            <InfoItem icon={<Server className="w-4 h-4" />} label="Company" value={agent.company_name ?? '—'} />
          </div>
          {/* Inline metrics summary */}
          {(agent.cpu_percent > 0 || agent.mem_percent > 0) && (
            <div className="flex gap-4 mt-4 border-t border-reap3r-border pt-4">
              {agent.cpu_percent > 0 && <MiniGauge label="CPU" value={agent.cpu_percent} />}
              {agent.mem_percent > 0 && <MiniGauge label="MEM" value={agent.mem_percent} />}
              {agent.disk_percent > 0 && <MiniGauge label="DISK" value={agent.disk_percent} />}
            </div>
          )}
        </Card>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-reap3r-border">
          {tabs.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm transition-colors border-b-2 -mb-px ${
                tab === t.key
                  ? 'text-reap3r-accent border-reap3r-accent'
                  : 'text-reap3r-muted border-transparent hover:text-reap3r-text'
              }`}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {tab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Capabilities */}
            <Card className="lg:col-span-2">
              <h4 className="text-xs font-medium text-reap3r-muted uppercase tracking-wider mb-3">Capabilities</h4>
              <div className="flex flex-wrap gap-1.5">
                {(Array.isArray(agent.capabilities) ? agent.capabilities : agent.capabilities?.modules ?? []).length > 0 ? (
                  (Array.isArray(agent.capabilities) ? agent.capabilities : agent.capabilities?.modules ?? []).map((cap: string) => (
                    <Badge key={cap} variant="accent">{cap}</Badge>
                  ))
                ) : (
                  <span className="text-xs text-reap3r-muted">No capabilities reported</span>
                )}
              </div>
              {/* Folders */}
              {agent.folders?.length > 0 && (
                <div className="mt-4">
                  <h4 className="text-xs font-medium text-reap3r-muted uppercase tracking-wider mb-2">Folders</h4>
                  <div className="flex flex-wrap gap-1.5">
                    {agent.folders.map((f: any) => <Badge key={f.id} variant="default">{f.name}</Badge>)}
                  </div>
                </div>
              )}
            </Card>

            {/* Actions Panel */}
            <Card>
              <h3 className="text-sm font-semibold text-reap3r-text mb-4">Remote Actions</h3>
              {!isOnline && (
                <div className="mb-4 bg-reap3r-warning/5 border border-reap3r-warning/20 rounded-lg px-3 py-2 text-xs text-reap3r-warning">
                  Agent is offline. Actions are disabled.
                </div>
              )}
              <div className="space-y-2">
                <ActionButton icon={<Terminal className="w-4 h-4" />} label="Run Script"
                  disabled={!isOnline || !hasCapability('run_script') || !canRunScript}
                  onClick={() => setScriptOpen(true)} />
                <ActionButton icon={<RotateCcw className="w-4 h-4" />} label="Reboot"
                  disabled={!isOnline || !hasCapability('reboot') || !canReboot}
                  onClick={() => sendAction(JobType.Reboot, { delay_sec: 0, reason: 'Reboot from UI' }, 'Manual reboot')} />
                <ActionButton icon={<PowerOff className="w-4 h-4" />} label="Shutdown"
                  disabled={!isOnline || !hasCapability('shutdown')}
                  onClick={() => sendAction(JobType.Shutdown, { delay_sec: 0, reason: 'Shutdown from UI' }, 'Manual shutdown')} />
                <ActionButton icon={<Package className="w-4 h-4" />} label="Collect Inventory"
                  disabled={!isOnline || !hasCapability('inventory')}
                  onClick={collectInventoryNow} />
                <ActionButton icon={<Shield className="w-4 h-4" />} label="Remote Shell"
                  disabled={!isOnline || !hasCapability('remote_shell')}
                  onClick={() => setTab('terminal')} />
                <ActionButton icon={<ScreenShare className="w-4 h-4" />} label="Remote Desktop"
                  disabled={!isOnline || !hasCapability('remote_desktop')}
                  onClick={() => { setTab('remote-desktop'); }} />
              </div>
            </Card>
          </div>
        )}

        {tab === 'terminal' && (
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-reap3r-text flex items-center gap-2">
                <Terminal className="w-4 h-4" /> Remote Terminal — {agent.hostname}
              </h3>
              {termHistory.length > 0 && (
                <Button variant="ghost" size="sm" onClick={() => setTermHistory([])}>Clear</Button>
              )}
            </div>

            {!isOnline && (
              <div className="mb-4 bg-reap3r-warning/5 border border-reap3r-warning/20 rounded-lg px-3 py-2 text-xs text-reap3r-warning flex items-center gap-2">
                <AlertCircle className="w-4 h-4" /> Agent is offline. Commands cannot be executed.
              </div>
            )}

            {/* Terminal Output Area */}
            <div className="bg-[#0d1117] border border-reap3r-border rounded-lg mb-3 max-h-[500px] overflow-y-auto font-mono text-xs">
              {termHistory.length === 0 ? (
                <div className="p-6 text-center text-gray-500">
                  <Terminal className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p>No commands yet. Type a command below to get started.</p>
                </div>
              ) : (
                <div className="p-3 space-y-3">
                  {termHistory.map((entry, i) => (
                    <div key={i} className="border-b border-gray-800 pb-3 last:border-0 last:pb-0">
                      {/* Command line */}
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-green-400">$</span>
                        <span className="text-gray-200 flex-1">{entry.cmd}</span>
                        <span className="flex items-center gap-1">
                          {entry.status === 'pending' && <Loader2 className="w-3 h-3 text-yellow-400 animate-spin" />}
                          {entry.status === 'dispatched' && <Loader2 className="w-3 h-3 text-blue-400 animate-spin" />}
                          {entry.status === 'running' && <Loader2 className="w-3 h-3 text-cyan-400 animate-spin" />}
                          {entry.status === 'completed' && entry.exit_code === 0 && <CheckCircle className="w-3 h-3 text-green-400" />}
                          {entry.status === 'completed' && entry.exit_code !== 0 && <XCircle className="w-3 h-3 text-orange-400" />}
                          {entry.status === 'failed' && <XCircle className="w-3 h-3 text-red-400" />}
                          <span className={`text-[10px] ${
                            entry.status === 'completed' && entry.exit_code === 0 ? 'text-green-500' :
                            entry.status === 'failed' ? 'text-red-500' :
                            entry.status === 'completed' ? 'text-orange-500' : 'text-gray-500'
                          }`}>
                            {entry.status === 'pending' ? 'queued...' :
                             entry.status === 'dispatched' ? 'dispatched...' :
                             entry.status === 'running' ? 'running...' :
                             entry.status === 'completed' ? `exit ${entry.exit_code} (${entry.duration_ms}ms)` :
                             'failed'}
                          </span>
                        </span>
                      </div>
                      {/* stdout */}
                      {entry.stdout && (
                        <pre className="text-gray-300 whitespace-pre-wrap ml-4 mt-1">{entry.stdout}</pre>
                      )}
                      {/* stderr */}
                      {entry.stderr && (
                        <pre className="text-red-400 whitespace-pre-wrap ml-4 mt-1">{entry.stderr}</pre>
                      )}
                    </div>
                  ))}
                  <div ref={termEndRef} />
                </div>
              )}
            </div>

            {/* Command Input */}
            <div className="flex gap-2 items-center">
              <select
                value={termInterpreter}
                onChange={(e) => setTermInterpreter(e.target.value as any)}
                className="px-2 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-xs text-reap3r-text focus:outline-none focus:ring-2 focus:ring-reap3r-accent/50"
              >
                <option value="powershell">PowerShell</option>
                <option value="bash">Bash</option>
                <option value="cmd">CMD</option>
                <option value="python">Python</option>
              </select>
              <div className="flex-1 relative">
                <input
                  ref={termInputRef}
                  type="text"
                  value={termCmd}
                  onChange={(e) => setTermCmd(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); runTerminalCommand(); } }}
                  placeholder={isOnline ? 'Type a command and press Enter...' : 'Agent offline'}
                  disabled={!isOnline || termRunning}
                  className="w-full px-3 py-2 bg-[#0d1117] border border-reap3r-border rounded-lg text-sm text-gray-200 font-mono placeholder:text-gray-600 focus:outline-none focus:ring-2 focus:ring-reap3r-accent/50 disabled:opacity-50"
                />
              </div>
              <Button
                onClick={() => runTerminalCommand()}
                disabled={!isOnline || !termCmd.trim() || termRunning}
                size="sm"
              >
                {termRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              </Button>
            </div>

            {/* Quick commands */}
            {isOnline && (
              <div className="flex flex-wrap gap-1.5 mt-3">
                <span className="text-[10px] text-reap3r-muted uppercase tracking-wider mr-1 self-center">Quick:</span>
                {[
                  { label: 'whoami', cmd: 'whoami' },
                  { label: 'hostname', cmd: 'hostname' },
                  { label: 'ipconfig', cmd: 'ipconfig' },
                  { label: 'systeminfo', cmd: 'systeminfo' },
                  { label: 'tasklist', cmd: 'tasklist' },
                  { label: 'Get-Process', cmd: 'Get-Process | Select-Object -First 20 Name, Id, CPU, WorkingSet' },
                  { label: 'Disk', cmd: 'Get-PSDrive -PSProvider FileSystem | Format-Table Name, Used, Free, @{N="Size";E={$_.Used+$_.Free}} -AutoSize'},
                ].map(q => (
                  <button key={q.label} onClick={() => runTerminalCommand(q.cmd)}
                    disabled={termRunning}
                    className="px-2 py-0.5 text-[10px] bg-reap3r-surface border border-reap3r-border rounded text-reap3r-muted hover:text-reap3r-text hover:border-reap3r-accent/30 transition-colors disabled:opacity-50"
                  >{q.label}</button>
                ))}
              </div>
            )}
          </Card>
        )}

        {tab === 'remote-desktop' && (
          <div ref={rdContainerRef} className={rdFullscreen ? 'fixed inset-0 z-50 bg-black flex flex-col' : ''}>
            {/* Toolbar */}
            <div className={`flex items-center justify-between gap-2 flex-wrap ${rdFullscreen ? 'px-4 py-2 bg-gray-900 border-b border-gray-700' : 'mb-3'}`}>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-reap3r-text flex items-center gap-2">
                  <ScreenShare className="w-4 h-4" /> Remote Desktop — {agent.hostname}
                </h3>
                <span className={`flex items-center gap-1 text-[10px] ${realtime.connected ? 'text-green-400' : 'text-red-400'}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${realtime.connected ? 'bg-green-400' : 'bg-red-400'}`} />
                  WS {realtime.connected ? 'ON' : 'OFF'}
                </span>
                {rdLoading && <Loader2 className="w-4 h-4 text-reap3r-accent animate-spin" />}
                {rdStreaming && (
                  <span className="flex items-center gap-1 text-[10px] text-green-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" /> LIVE
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                {/* Quality */}
                <label className="text-[10px] text-reap3r-muted flex items-center gap-1">
                  Quality
                  <select value={rdQuality} onChange={e => setRdQuality(Number(e.target.value))}
                    className="px-1 py-0.5 bg-reap3r-surface border border-reap3r-border rounded text-xs text-reap3r-text">
                    <option value={30}>Low</option>
                    <option value={50}>Medium</option>
                    <option value={70}>High</option>
                    <option value={90}>Ultra</option>
                  </select>
                </label>
                {/* Scale */}
                <label className="text-[10px] text-reap3r-muted flex items-center gap-1">
                  Scale
                  <select value={rdScale} onChange={e => setRdScale(Number(e.target.value))}
                    className="px-1 py-0.5 bg-reap3r-surface border border-reap3r-border rounded text-xs text-reap3r-text">
                    <option value={30}>30%</option>
                    <option value={40}>40%</option>
                    <option value={50}>50%</option>
                    <option value={70}>70%</option>
                    <option value={100}>100%</option>
                  </select>
                </label>
                {/* FPS */}
                <label className="text-[10px] text-reap3r-muted flex items-center gap-1">
                  FPS
                  <select value={rdFps} onChange={e => setRdFps(Number(e.target.value))}
                    className="px-1 py-0.5 bg-reap3r-surface border border-reap3r-border rounded text-xs text-reap3r-text">
                    <option value={1}>1</option>
                    <option value={2}>2</option>
                    <option value={3}>3</option>
                    <option value={5}>5</option>
                  </select>
                </label>
                {/* Monitor selector */}
                <label className="text-[10px] text-reap3r-muted flex items-center gap-1">
                  <Monitor className="w-3 h-3" />
                  Screen
                  <select
                    value={rdSelectedMonitor}
                    onChange={e => setRdSelectedMonitor(Number(e.target.value))}
                    className="px-1 py-0.5 bg-reap3r-surface border border-reap3r-border rounded text-xs text-reap3r-text"
                  >
                    <option value={-1}>All screens</option>
                    {rdMonitors.map(m => (
                      <option key={m.index} value={m.index}>
                        {m.primary ? '★ ' : ''}Screen {m.index + 1} ({m.width}x{m.height})
                      </option>
                    ))}
                  </select>
                  {rdMonitorsLoading && <Loader2 className="w-3 h-3 animate-spin text-reap3r-accent" />}
                  <button
                    onClick={fetchMonitors}
                    disabled={rdMonitorsLoading}
                    className="p-0.5 text-reap3r-muted hover:text-reap3r-accent transition-colors disabled:opacity-50"
                    title="Refresh monitor list"
                  >
                    <RefreshCw className="w-3 h-3" />
                  </button>
                </label>
                {/* Stream / Stop / Screenshot buttons */}
                {!rdStreaming ? (
                  <>
                    <Button size="sm" onClick={startRdStream} disabled={!isOnline || rdLoading}>
                      <Play className="w-4 h-4" /> Stream
                    </Button>
                    <Button size="sm" variant="ghost" onClick={captureScreenshot} disabled={!isOnline || rdLoading}>
                      <Camera className="w-4 h-4" /> Screenshot
                    </Button>
                  </>
                ) : (
                  <Button size="sm" variant="danger" onClick={stopRdStream}>
                    <Square className="w-4 h-4" /> Stop
                  </Button>
                )}
                {/* Fullscreen toggle */}
                <button onClick={() => setRdFullscreen(p => !p)}
                  className="p-1 text-reap3r-muted hover:text-reap3r-text transition-colors">
                  {rdFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Error */}
            {rdError && (
              <div className={`bg-red-500/5 border border-red-500/20 rounded-lg px-3 py-2 text-xs text-red-400 flex items-center gap-2 ${rdFullscreen ? 'mx-4' : 'mb-3'}`}>
                <AlertCircle className="w-4 h-4" /> {rdError}
              </div>
            )}

            {!isOnline && (
              <div className={`bg-reap3r-warning/5 border border-reap3r-warning/20 rounded-lg px-3 py-2 text-xs text-reap3r-warning flex items-center gap-2 ${rdFullscreen ? 'mx-4' : 'mb-3'}`}>
                <AlertCircle className="w-4 h-4" /> Agent is offline. Remote desktop is unavailable.
              </div>
            )}

            {/* Video/Screenshot Display */}
            <div className={`bg-[#0d1117] border border-reap3r-border rounded-lg overflow-hidden flex items-center justify-center ${
              rdFullscreen ? 'flex-1 mx-4 mb-4 mt-2' : 'min-h-[400px]'
            }`}>
              {!rdFrame && !rdLoading && !rdStreaming && (
                <div className="text-center py-16">
                  <ScreenShare className="w-12 h-12 mx-auto text-gray-600 mb-3" />
                  <p className="text-sm text-gray-500 mb-2">View remote desktop in real-time</p>
                  <p className="text-xs text-gray-600 mb-4">Click &quot;Stream&quot; for live video or &quot;Screenshot&quot; for a single capture</p>
                  {isOnline && (
                    <div className="flex gap-2 justify-center">
                      <Button onClick={startRdStream} size="sm">
                        <Play className="w-4 h-4" /> Start Stream
                      </Button>
                      <Button onClick={captureScreenshot} size="sm" variant="ghost">
                        <Camera className="w-4 h-4" /> Screenshot
                      </Button>
                    </div>
                  )}
                </div>
              )}
              {(rdLoading || (rdStreaming && !rdFrame)) && (
                <div className="text-center py-16">
                  <Loader2 className="w-10 h-10 mx-auto text-reap3r-accent animate-spin mb-3" />
                  <p className="text-sm text-gray-500">{rdLoading ? 'Creating stream job...' : 'Waiting for first frame from agent...'}</p>
                  <p className="text-xs text-gray-600 mt-1">This may take a few seconds while the agent prepares the capture</p>
                </div>
              )}
              {rdFrame && (
                <img
                  src={rdFrame}
                  alt="Remote Desktop"
                  className="max-w-full max-h-full object-contain"
                  draggable={false}
                />
              )}
            </div>

            {/* Status bar */}
            <div className={`flex items-center gap-3 mt-2 text-[10px] text-reap3r-muted ${rdFullscreen ? 'px-4 pb-2' : ''}`}>
              <span className="flex items-center gap-1">
                <Camera className="w-3 h-3" /> Quality: {rdQuality}% &middot; Scale: {rdScale}% &middot; FPS: {rdFps}
              </span>
              <span className="flex items-center gap-1">
                <Monitor className="w-3 h-3" /> {rdSelectedMonitor === -1 ? 'All screens' : `Screen ${rdSelectedMonitor + 1}`}
                {rdMonitors.length > 0 && ` (${rdMonitors.length} detected)`}
              </span>
              {rdStreaming && (
                <span className="flex items-center gap-1 text-green-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" /> Streaming &middot; {rdFrameCount} frames received
                </span>
              )}
              <span className="ml-auto">Agent: {agent.os === 'windows' ? 'Windows' : agent.os}</span>
            </div>
          </div>
        )}

        {/* ── File Explorer Tab ── */}
        {tab === 'file-explorer' && (
          <Card>
            {/* Toolbar */}
            <div className="flex items-center gap-2 mb-4 flex-wrap">
              <button onClick={feGoBack} disabled={feHistory.length === 0 || feLoading}
                className="p-1.5 rounded hover:bg-reap3r-hover text-reap3r-muted disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                title="Back">
                <ArrowLeft className="w-4 h-4" />
              </button>
              <button onClick={feGoUp} disabled={feLoading}
                className="p-1.5 rounded hover:bg-reap3r-hover text-reap3r-muted disabled:opacity-30 transition-colors"
                title="Up">
                <ArrowUp className="w-4 h-4" />
              </button>
              <button onClick={feGoHome} disabled={feLoading}
                className="p-1.5 rounded hover:bg-reap3r-hover text-reap3r-muted disabled:opacity-30 transition-colors"
                title="Home">
                <Home className="w-4 h-4" />
              </button>
              <button onClick={() => feListDir(fePath)} disabled={feLoading}
                className="p-1.5 rounded hover:bg-reap3r-hover text-reap3r-muted disabled:opacity-30 transition-colors"
                title="Refresh">
                <RefreshCw className={`w-4 h-4 ${feLoading ? 'animate-spin' : ''}`} />
              </button>
              <form className="flex-1 min-w-[200px]" onSubmit={e => { e.preventDefault(); feListDir(fePathInput); }}>
                <input
                  value={fePathInput}
                  onChange={e => setFePathInput(e.target.value)}
                  className="w-full px-3 py-1.5 bg-reap3r-surface border border-reap3r-border rounded text-sm text-reap3r-text font-mono focus:outline-none focus:ring-1 focus:ring-reap3r-accent/50"
                  placeholder="Path..."
                />
              </form>
              {/* Upload */}
              <input type="file" ref={feUploadRef} className="hidden"
                onChange={e => { if (e.target.files?.[0]) feUpload(e.target.files[0]); e.target.value = ''; }} />
              <Button size="sm" variant="ghost" onClick={() => feUploadRef.current?.click()} disabled={!isOnline || feUploading}>
                {feUploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                {feUploading ? 'Uploading...' : 'Upload'}
              </Button>
            </div>

            {/* Error */}
            {feError && (
              <div className="bg-red-500/5 border border-red-500/20 rounded-lg px-3 py-2 text-xs text-red-400 flex items-center gap-2 mb-3">
                <AlertCircle className="w-4 h-4 flex-shrink-0" /> {feError}
                <button onClick={() => setFeError(null)} className="ml-auto text-red-400 hover:text-red-300">&times;</button>
              </div>
            )}

            {/* Path breadcrumb */}
            <div className="text-xs text-reap3r-muted mb-3 font-mono truncate" title={fePath}>
              <FolderOpen className="w-3 h-3 inline mr-1" /> {fePath}
              <span className="ml-2 text-reap3r-muted/50">{feFiles.length} items</span>
            </div>

            {/* File listing */}
            {feLoading && feFiles.length === 0 ? (
              <div className="text-center py-12">
                <Loader2 className="w-8 h-8 mx-auto text-reap3r-accent animate-spin mb-3" />
                <p className="text-sm text-reap3r-muted">Loading directory...</p>
              </div>
            ) : feFiles.length === 0 && !feError ? (
              <div className="text-center py-12">
                <FolderOpen className="w-10 h-10 mx-auto text-reap3r-muted mb-3" />
                <p className="text-sm text-reap3r-muted">Empty directory</p>
              </div>
            ) : (
              <div className="border border-reap3r-border rounded-lg overflow-hidden">
                {/* Header */}
                <div className="grid grid-cols-12 gap-2 px-3 py-2 bg-reap3r-surface text-[10px] text-reap3r-muted uppercase tracking-wider font-medium border-b border-reap3r-border">
                  <div className="col-span-6">Name</div>
                  <div className="col-span-2">Size</div>
                  <div className="col-span-3">Modified</div>
                  <div className="col-span-1 text-right">Actions</div>
                </div>
                {/* Rows */}
                <div className="max-h-[500px] overflow-y-auto divide-y divide-reap3r-border/50">
                  {feFiles.map((f) => (
                    <div key={f.name}
                      className="grid grid-cols-12 gap-2 px-3 py-2 hover:bg-reap3r-hover transition-colors items-center group text-sm"
                    >
                      <div className="col-span-6 flex items-center gap-2 min-w-0">
                        {f.type === 'directory'
                          ? <Folder className="w-4 h-4 text-reap3r-accent flex-shrink-0" />
                          : <File className="w-4 h-4 text-reap3r-muted flex-shrink-0" />}
                        {f.type === 'directory' ? (
                          <button
                            onClick={() => feNavigate(f.name)}
                            className="text-reap3r-text hover:text-reap3r-accent truncate text-left transition-colors"
                            title={f.name}
                          >
                            {f.name}
                          </button>
                        ) : (
                          <span className="text-reap3r-text truncate" title={f.name}>{f.name}</span>
                        )}
                      </div>
                      <div className="col-span-2 text-xs text-reap3r-muted">
                        {f.type === 'directory' ? '—' : formatBytes(f.size)}
                      </div>
                      <div className="col-span-3 text-xs text-reap3r-muted truncate" title={f.modified}>
                        {f.modified ? new Date(f.modified).toLocaleString() : '—'}
                      </div>
                      <div className="col-span-1 flex justify-end">
                        {f.type === 'file' && (
                          <button
                            onClick={() => feDownload(f.name)}
                            disabled={feDownloading === f.name}
                            className="p-1 rounded hover:bg-reap3r-accent/10 text-reap3r-muted hover:text-reap3r-accent opacity-0 group-hover:opacity-100 transition-all disabled:opacity-50"
                            title={`Download ${f.name}`}
                          >
                            {feDownloading === f.name
                              ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                              : <Download className="w-3.5 h-3.5" />}
                          </button>
                        )}
                        {f.type === 'directory' && (
                          <button
                            onClick={() => feNavigate(f.name)}
                            className="p-1 rounded hover:bg-reap3r-accent/10 text-reap3r-muted hover:text-reap3r-accent opacity-0 group-hover:opacity-100 transition-all"
                            title={`Open ${f.name}`}
                          >
                            <FolderOpen className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Card>
        )}

        {tab === 'inventory' && (
          <InventoryTab inventory={inventory} onRefresh={collectInventoryNow} />
        )}

        {tab === 'metrics' && (
          <MetricsTab data={metricsData} period={metricsPeriod} onPeriodChange={setMetricsPeriod} />
        )}

        {tab === 'jobs' && (
          <Card>
            <h3 className="text-sm font-semibold text-reap3r-text mb-4">Job History</h3>
            <JobList jobs={recentJobs} />
          </Card>
        )}

        {/* Run Script Dialog */}
        {scriptOpen && (
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-reap3r-text">Run Script on {agent.hostname}</h3>
              <Button variant="ghost" size="sm" onClick={() => setScriptOpen(false)}>Cancel</Button>
            </div>
            <div className="space-y-3">
              <div className="flex gap-2">
                {(['bash', 'powershell', 'python'] as const).map((i) => (
                  <button key={i} onClick={() => setInterpreter(i)}
                    className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                      interpreter === i
                        ? 'bg-reap3r-accent/10 text-reap3r-accent border border-reap3r-accent/20'
                        : 'text-reap3r-muted hover:text-reap3r-text bg-reap3r-surface border border-reap3r-border'
                    }`}>{i}</button>
                ))}
              </div>
              <textarea
                className="w-full h-40 px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-reap3r-text font-mono placeholder:text-reap3r-muted/50 focus:outline-none focus:ring-2 focus:ring-reap3r-accent/50 resize-y"
                placeholder={`Enter your ${interpreter} script...`}
                value={script}
                onChange={(e) => setScript(e.target.value)}
              />
              <div className="flex justify-end">
                <Button onClick={runScript} loading={submitting} disabled={!script.trim()}>
                  <Play className="w-4 h-4" /> Execute
                </Button>
              </div>
            </div>
          </Card>
        )}
      </div>
    </>
  );
}

// ── Inventory Tab ──────────────────────────────

function InventoryTab({ inventory, onRefresh }: { inventory: any; onRefresh: () => void }) {
  if (!inventory?.inventory || Object.keys(inventory.inventory).length === 0) {
    return (
      <Card>
        <div className="text-center py-8">
          <Package className="w-10 h-10 mx-auto text-reap3r-muted mb-3" />
          <p className="text-sm text-reap3r-muted mb-4">No inventory data collected yet.</p>
          <Button onClick={onRefresh} size="sm">
            <RefreshCw className="w-4 h-4" /> Collect Now
          </Button>
        </div>
      </Card>
    );
  }

  const inv = inventory.inventory;
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* System Info */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3 flex items-center gap-2">
          <Server className="w-4 h-4 text-reap3r-accent" /> System
        </h3>
        <div className="space-y-2 text-sm">
          <KV label="Hostname" value={inv.hostname} />
          <KV label="OS" value={`${inv.os} ${inv.os_version}`} />
          <KV label="Architecture" value={inv.arch} />
          <KV label="CPU" value={`${inv.cpu_model} (${inv.cpu_cores} cores)`} />
          <KV label="Memory" value={inv.memory_total_bytes ? `${(inv.memory_total_bytes / 1073741824).toFixed(1)} GB` : '—'} />
          <KV label="Processes" value={inv.process_count?.toString() ?? '—'} />
        </div>
      </Card>

      {/* Disks */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3 flex items-center gap-2">
          <HardDrive className="w-4 h-4 text-reap3r-accent" /> Storage
        </h3>
        {inv.disks?.length > 0 ? (
          <div className="space-y-3">
            {inv.disks.map((d: any, i: number) => {
              const used = d.total_bytes - d.available_bytes;
              const pct = d.total_bytes > 0 ? (used / d.total_bytes) * 100 : 0;
              return (
                <div key={i}>
                  <div className="flex justify-between text-xs text-reap3r-muted mb-1">
                    <span>{d.mount_point} ({d.fs_type})</span>
                    <span>{(used / 1073741824).toFixed(1)} / {(d.total_bytes / 1073741824).toFixed(1)} GB</span>
                  </div>
                  <div className="h-2 bg-reap3r-border rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${pct > 90 ? 'bg-reap3r-danger' : pct > 70 ? 'bg-reap3r-warning' : 'bg-reap3r-accent'}`}
                      style={{ width: `${Math.min(pct, 100)}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-sm text-reap3r-muted">No disk data.</p>
        )}
      </Card>

      {/* Network Interfaces */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3 flex items-center gap-2">
          <Wifi className="w-4 h-4 text-reap3r-accent" /> Network
        </h3>
        {inv.network_interfaces?.length > 0 ? (
          <div className="space-y-2">
            {inv.network_interfaces.map((n: any, i: number) => (
              <div key={i} className="flex items-center justify-between py-1.5 border-b border-reap3r-border last:border-0">
                <div>
                  <p className="text-sm text-reap3r-text font-medium">{n.name}</p>
                  <p className="text-xs text-reap3r-muted">{n.mac ?? '—'}</p>
                </div>
                <div className="text-right text-xs text-reap3r-muted">
                  <p>RX: {formatBytes(n.rx_bytes)}</p>
                  <p>TX: {formatBytes(n.tx_bytes)}</p>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-reap3r-muted">No network data.</p>
        )}
      </Card>

      {/* Top Processes */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3 flex items-center gap-2">
          <Cpu className="w-4 h-4 text-reap3r-accent" /> Top Processes
        </h3>
        {inv.top_processes?.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-reap3r-muted border-b border-reap3r-border">
                  <th className="text-left py-1.5 pr-3">PID</th>
                  <th className="text-left py-1.5 pr-3">Name</th>
                  <th className="text-right py-1.5 pr-3">CPU%</th>
                  <th className="text-right py-1.5">Memory</th>
                </tr>
              </thead>
              <tbody>
                {inv.top_processes.slice(0, 15).map((p: any, i: number) => (
                  <tr key={i} className="border-b border-reap3r-border/50">
                    <td className="py-1.5 pr-3 text-reap3r-muted">{p.pid}</td>
                    <td className="py-1.5 pr-3 text-reap3r-text font-medium truncate max-w-[150px]">{p.name}</td>
                    <td className="py-1.5 pr-3 text-right">{p.cpu_percent?.toFixed(1)}</td>
                    <td className="py-1.5 text-right text-reap3r-muted">{formatBytes(p.memory_bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-reap3r-muted">No process data.</p>
        )}
      </Card>
    </div>
  );
}

// ── Metrics Tab ──────────────────────────────

function MetricsTab({ data, period, onPeriodChange }: { data: any[]; period: number; onPeriodChange: (h: number) => void }) {
  if (data.length === 0) {
    return (
      <Card>
        <div className="text-center py-8">
          <Activity className="w-10 h-10 mx-auto text-reap3r-muted mb-3" />
          <p className="text-sm text-reap3r-muted">No metrics data available yet. Metrics will appear once the agent starts sending telemetry.</p>
        </div>
      </Card>
    );
  }

  const latest = data[data.length - 1];
  const cpuValues = data.map(d => d.cpu_percent).filter(Boolean);
  const memValues = data.map(d => d.memory_used_mb).filter(Boolean);
  const avgCpu = cpuValues.length > 0 ? cpuValues.reduce((a: number, b: number) => a + b, 0) / cpuValues.length : 0;
  const maxCpu = cpuValues.length > 0 ? Math.max(...cpuValues) : 0;
  const avgMem = memValues.length > 0 ? memValues.reduce((a: number, b: number) => a + b, 0) / memValues.length : 0;

  return (
    <div className="space-y-6">
      {/* Period selector */}
      <div className="flex gap-2">
        {[1, 6, 24, 72, 168].map((h) => (
          <button key={h} onClick={() => onPeriodChange(h)}
            className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
              period === h
                ? 'bg-reap3r-accent/10 text-reap3r-accent border border-reap3r-accent/20'
                : 'text-reap3r-muted bg-reap3r-surface border border-reap3r-border hover:text-reap3r-text'
            }`}>{h < 24 ? `${h}h` : `${h / 24}d`}</button>
        ))}
      </div>

      {/* Stats summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="!p-4">
          <p className="text-xs text-reap3r-muted">Avg CPU</p>
          <p className="text-xl font-bold text-reap3r-text">{avgCpu.toFixed(1)}%</p>
        </Card>
        <Card className="!p-4">
          <p className="text-xs text-reap3r-muted">Max CPU</p>
          <p className="text-xl font-bold text-reap3r-text">{maxCpu.toFixed(1)}%</p>
        </Card>
        <Card className="!p-4">
          <p className="text-xs text-reap3r-muted">Avg Memory</p>
          <p className="text-xl font-bold text-reap3r-text">{avgMem.toFixed(0)} MB</p>
        </Card>
        <Card className="!p-4">
          <p className="text-xs text-reap3r-muted">Data Points</p>
          <p className="text-xl font-bold text-reap3r-text">{data.length}</p>
        </Card>
      </div>

      {/* ASCII sparkline chart */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3">CPU Usage Over Time</h3>
        <SparklineChart values={cpuValues} max={100} label="%" color="accent" height={80} />
      </Card>

      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3">Memory Usage Over Time</h3>
        <SparklineChart values={memValues} max={latest?.memory_total_mb ?? Math.max(...memValues)} label=" MB" color="accent" height={80} />
      </Card>

      {/* Latest raw data */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3">Latest Metrics</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
          <KV label="CPU" value={`${latest?.cpu_percent?.toFixed(1) ?? '—'}%`} />
          <KV label="Memory" value={latest?.memory_used_mb ? `${latest.memory_used_mb.toFixed(0)} / ${latest.memory_total_mb?.toFixed(0)} MB` : '—'} />
          <KV label="Processes" value={latest?.process_count?.toString() ?? '—'} />
          <KV label="Load 1m" value={latest?.load_avg_1m?.toFixed(2) ?? '—'} />
        </div>
      </Card>
    </div>
  );
}

// ── Sparkline Chart (pure CSS/div) ───────────

function SparklineChart({ values, max, label, color, height }: {
  values: number[];
  max: number;
  label: string;
  color: string;
  height: number;
}) {
  if (values.length === 0) return <p className="text-sm text-reap3r-muted">No data</p>;

  // Downsample to max 100 bars
  const step = Math.max(1, Math.floor(values.length / 100));
  const sampled = values.filter((_, i) => i % step === 0);

  return (
    <div className="flex items-end gap-px" style={{ height }}>
      {sampled.map((v, i) => {
        const pct = max > 0 ? Math.min((v / max) * 100, 100) : 0;
        return (
          <div key={i} className="flex-1 min-w-[2px] group relative">
            <div
              className={`w-full rounded-t-sm ${pct > 80 ? 'bg-reap3r-danger' : pct > 60 ? 'bg-reap3r-warning' : 'bg-reap3r-accent'}`}
              style={{ height: `${pct}%` }}
            />
            <div className="absolute -top-6 left-1/2 -translate-x-1/2 bg-reap3r-card text-reap3r-text text-[10px] px-1 rounded opacity-0 group-hover:opacity-100 pointer-events-none whitespace-nowrap">
              {v.toFixed(1)}{label}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Job List ─────────────────────────────────

function JobList({ jobs }: { jobs: any[] }) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (jobs.length === 0) {
    return <p className="text-sm text-reap3r-muted py-4 text-center">No jobs for this agent yet.</p>;
  }

  return (
    <div className="divide-y divide-reap3r-border">
      {jobs.map((job) => (
        <div key={job.id}>
          <button
            className="flex items-center gap-3 py-3 w-full text-left hover:bg-reap3r-hover px-2 -mx-2 rounded transition-colors"
            onClick={() => setExpandedId(expandedId === job.id ? null : job.id)}
          >
            {expandedId === job.id ? <ChevronDown className="w-4 h-4 text-reap3r-muted" /> : <ChevronRight className="w-4 h-4 text-reap3r-muted" />}
            <Badge variant={job.status === 'success' || job.status === 'completed' ? 'success' : job.status === 'failed' ? 'danger' : job.status === 'running' ? 'accent' : 'default'}>
              {job.status}
            </Badge>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-reap3r-text">{job.type}</p>
              {job.reason && <p className="text-xs text-reap3r-muted truncate">{job.reason}</p>}
            </div>
            <span className="text-xs text-reap3r-muted">{formatDate(job.created_at)}</span>
          </button>
          {expandedId === job.id && job.result && (
            <div className="px-10 pb-3">
              <pre className="text-xs bg-reap3r-surface border border-reap3r-border rounded-lg p-3 overflow-x-auto text-reap3r-text max-h-48">
                {typeof job.result === 'string' ? job.result : JSON.stringify(job.result, null, 2)}
              </pre>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Utility Components ──────────────────────

function InfoItem({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className="text-reap3r-muted">{icon}</div>
      <div>
        <p className="text-[10px] text-reap3r-muted uppercase tracking-wider">{label}</p>
        <p className="text-sm text-reap3r-text font-medium">{value}</p>
      </div>
    </div>
  );
}

function KV({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between items-center">
      <span className="text-reap3r-muted">{label}</span>
      <span className="text-reap3r-text font-medium">{value}</span>
    </div>
  );
}

function MiniGauge({ label, value }: { label: string; value: number }) {
  const pct = Math.min(Math.round(value), 100);
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-reap3r-muted w-8">{label}</span>
      <div className="w-20 h-1.5 bg-reap3r-border rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${pct > 90 ? 'bg-reap3r-danger' : pct > 70 ? 'bg-reap3r-warning' : 'bg-reap3r-accent'}`}
          style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-reap3r-text font-medium">{pct}%</span>
    </div>
  );
}

function ActionButton({ icon, label, disabled, onClick }: {
  icon: React.ReactNode;
  label: string;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed text-reap3r-text hover:bg-reap3r-hover border border-reap3r-border"
    >
      {icon}
      {label}
    </button>
  );
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
}
