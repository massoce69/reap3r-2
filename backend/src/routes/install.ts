// ─────────────────────────────────────────────
// MASSVISION Reap3r — Agent Install Scripts
// ─────────────────────────────────────────────
//
// These endpoints are used for copy/paste one-liners from the UI.
// They are intentionally unauthenticated: possession of an enrollment token is the gate.
//
import { FastifyInstance } from 'fastify';

function firstHeader(v: unknown): string | undefined {
  if (!v) return undefined;
  if (Array.isArray(v)) return String(v[0] ?? '');
  return String(v);
}

function publicBaseUrl(request: any): string {
  const proto = (firstHeader(request.headers['x-forwarded-proto']) || request.protocol || 'http')
    .split(',')[0]
    .trim();
  const host = (firstHeader(request.headers['x-forwarded-host']) || firstHeader(request.headers.host) || '')
    .split(',')[0]
    .trim();
  return host ? `${proto}://${host}` : (process.env.API_BASE_URL || 'http://localhost:4000');
}

export default async function installRoutes(fastify: FastifyInstance) {
  fastify.get('/api/install/linux', async (request, reply) => {
    const q = request.query as any;
    const token = String(q.token ?? '');
    const base = publicBaseUrl(request);

    // Keep the script dependency-light. It downloads the agent binary from this server.
    const script = `#!/usr/bin/env bash
set -euo pipefail

TOKEN="${token}"
SERVER="${base}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2;;
    --server) SERVER="$2"; shift 2;;
    *) shift;;
  esac
done

if [[ -z "$TOKEN" ]]; then
  echo "Missing token. Provide ?token=... or --token ..." >&2
  exit 1
fi

INSTALL_DIR="/opt/massvision/reap3r"
BIN_PATH="$INSTALL_DIR/reap3r-agent"
ENV_DIR="/etc/massvision/reap3r"
ENV_FILE="$ENV_DIR/agent.env"

echo "[reap3r] Installing agent to $BIN_PATH"
mkdir -p "$INSTALL_DIR"
mkdir -p "$ENV_DIR"

echo "[reap3r] Downloading agent binary..."
curl -fsSL "$SERVER/api/agent-binary/download?os=linux&arch=x86_64" -o "$BIN_PATH"
chmod 755 "$BIN_PATH"

WS_SCHEME="ws"
if [[ "$SERVER" == https://* ]]; then WS_SCHEME="wss"; fi
WS_URL="$WS_SCHEME://$(echo "$SERVER" | sed -E 's#^https?://##')/ws/agent"

cat > "$ENV_FILE" <<EOF
REAP3R_SERVER=$WS_URL
REAP3R_TOKEN=$TOKEN
EOF
chmod 600 "$ENV_FILE"

cat > /etc/systemd/system/reap3r-agent.service <<EOF
[Unit]
Description=MASSVISION Reap3r Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_PATH
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now reap3r-agent.service

echo "[reap3r] Installed. Status:"
systemctl --no-pager --full status reap3r-agent.service || true
`;

    reply.header('Content-Type', 'text/plain; charset=utf-8');
    reply.header('Cache-Control', 'no-store');
    return reply.send(script);
  });

  fastify.get('/api/install/windows', async (_request, reply) => {
    const q = _request.query as any;
    const token = String(q.token ?? '');
    const base = publicBaseUrl(_request);

    // Build the PS1 using array join to avoid ALL backtick / escaping issues in TS template strings.
    // Each entry is one line of the PowerShell script.
    const lines: string[] = [
      `param(`,
      `  [string]$Token  = "${token}",`,
      `  [string]$Server = "${base}"`,
      `)`,
      ``,
      `# IMPORTANT: keep Continue for the whole script — sc.exe / taskkill write to`,
      `# stderr even on success and "Stop" would turn those into terminating errors`,
      `# that silently kill Invoke-Expression scripts.`,
      `$ErrorActionPreference = "Continue"`,
      `try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}`,
      ``,
      `function Write-Step([string]$msg) { Write-Host "" ; Write-Host "[reap3r] $msg" -ForegroundColor Cyan }`,
      `function Write-OK([string]$msg)   { Write-Host "    OK  $msg" -ForegroundColor Green }`,
      `function Write-Fail([string]$msg) { Write-Host "    ERR $msg" -ForegroundColor Red }`,
      ``,
      `# Run a native executable with a hard timeout so the installer never hangs`,
      `function Invoke-NativeTimeout([string]$File, [string]$Args, [int]$TimeoutMs = 2000) {`,
      `  try {`,
      `    $p = Start-Process -FilePath $File -ArgumentList $Args -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue`,
      `    if (-not $p) { return }`,
      `    $sec = [Math]::Max(1, [int][Math]::Ceiling($TimeoutMs / 1000.0))`,
      `    Wait-Process -Id $p.Id -Timeout $sec -ErrorAction SilentlyContinue | Out-Null`,
      `    try { $p.Refresh() } catch {}`,
      `    if (-not $p.HasExited) {`,
      `      Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue`,
      `    }`,
      `  } catch {}`,
      `}`,
      ``,
      `# ── Admin check ──────────────────────────────────────────────────────────────`,
      `$wp = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())`,
      `if (-not $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {`,
      `  Write-Fail "Please run PowerShell as Administrator (right-click -> Run as administrator)."`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `if ([string]::IsNullOrWhiteSpace($Token)) {`,
      `  Write-Fail "Missing enrollment token."`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `$Server = $Server.TrimEnd('/')`,
      `if (-not ($Server -match '^https?://')) {`,
      `  Write-Fail "Server URL must start with https:// or http://"`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `# Convert http(s):// to ws(s)://`,
      `$wsUrl = ($Server -replace '^http://', 'ws://') -replace '^https://', 'wss://'`,
      `# MassVision agent expects /ws/agents`,
      `$wsUrl = "$wsUrl/ws/agents"`,
      ``,
      `# MassVision Agent v2 paths`,
      `$installDir = Join-Path $env:ProgramFiles 'MassVision'`,
      `$exePath    = Join-Path $installDir 'massvision-agent.exe'`,
      `# IMPORTANT: we download/run the installer binary from a temp path so that`,
      `# 'massvision-agent install' can copy itself into Program Files without file locks.`,
      `$dlDir  = Join-Path $env:TEMP 'MassVision'`,
      `$runExe = Join-Path $dlDir ("massvision-agent-" + [Guid]::NewGuid().ToString('N') + '.exe')`,
      `$dataDirPrimary = Join-Path $env:ProgramData 'MassVision'`,
      `$dataDirLegacy1 = Join-Path $env:ProgramData 'XefiAgent2'`,
      `$dataDirLegacy2 = Join-Path $env:ProgramData 'Reap3r'`,
      `$dataDir = $dataDirPrimary`,
      `$logFiles = @(`,
      `  (Join-Path $dataDirPrimary 'logs\\massvision-agent.log'),`,
      `  (Join-Path $dataDirLegacy1 'logs\\agent.log'),`,
      `  (Join-Path $dataDirLegacy2 'logs\\agent.log')`,
      `)`,
      `$configFiles = @(`,
      `  (Join-Path $dataDirPrimary 'config.toml'),`,
      `  (Join-Path $dataDirLegacy1 'agent.conf'),`,
      `  (Join-Path $dataDirLegacy2 'agent.conf')`,
      `)`,
      `$serviceCandidates = @('MassVisionAgent','XEFI-Agent-2','MASSVISION-Reap3r-Agent','Reap3rAgent','ReaP3rAgent','xefi-agent-2')`,
      `$serviceName = $serviceCandidates[0]`,
      `$logFile    = $logFiles[0]`,
      ``,
      `# ── Add Windows Defender exclusions ──────────────────────────────────────────`,
      `Write-Step "Adding Windows Defender exclusions..."`,
      `try {`,
      `  Add-MpPreference -ExclusionPath $installDir -ErrorAction SilentlyContinue`,
      `  Add-MpPreference -ExclusionPath $exePath -ErrorAction SilentlyContinue`,
      `  Add-MpPreference -ExclusionProcess 'reap3r-agent.exe' -ErrorAction SilentlyContinue`,
      `  Add-MpPreference -ExclusionProcess 'xefi-agent-2.exe' -ErrorAction SilentlyContinue`,
      `  Add-MpPreference -ExclusionProcess 'massvision-agent.exe' -ErrorAction SilentlyContinue`,
      `  Write-OK "Windows Defender exclusions added"`,
      `} catch {`,
      `  Write-Host "    WARN Could not add Windows Defender exclusions (Defender may not be active)" -ForegroundColor Yellow`,
      `}`,
      ``,
      `# ── Create directories ────────────────────────────────────────────────────────`,
      `Write-Step "Creating directories..."`,
      `foreach ($d in @(`,
      `  $installDir,`,
      `  $dlDir,`,
      `  $dataDirPrimary, $dataDirLegacy1, $dataDirLegacy2,`,
      `  (Join-Path $dataDirPrimary 'logs'),`,
      `  (Join-Path $dataDirLegacy1 'logs'),`,
      `  (Join-Path $dataDirLegacy2 'logs')`,
      `)) {`,
      `  if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }`,
      `}`,
      `try {`,
      `  $acl = Get-Acl $dataDirPrimary`,
      `  $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow"`,
      `  $acl.SetAccessRule($rule)`,
      `  Set-Acl $dataDirPrimary $acl`,
      `} catch {}`,
      `Write-OK $installDir`,
      ``,
      `# ── Remove old config ───────────────────────────────────────────────────────`,
      `Write-Step "Removing old config..."`,
      `foreach ($cfg in $configFiles) {`,
      `  if (Test-Path $cfg) { Remove-Item $cfg -Force -ErrorAction SilentlyContinue }`,
      `}`,
      `Write-OK "Config cleaned"`,
      ``,
      `# ── Cleanup: stop & remove existing agent ─────────────────────────────────`,
      `Write-Step "Stopping existing agent..."`,
      ``,
      `# AGGRESSIVE CLEANUP: Kill processes FIRST to release file locks and ensure service stops don't hang`,
      `Invoke-NativeTimeout 'taskkill.exe' '/F /IM reap3r-agent.exe /T' 2000`,
      `Invoke-NativeTimeout 'taskkill.exe' '/F /IM xefi-agent-2.exe /T' 2000`,
      `Invoke-NativeTimeout 'taskkill.exe' '/F /IM massvision-agent.exe /T' 2000`,
      ``,
      `# Stop & remove services`,
      `foreach ($candidate in $serviceCandidates) {`,
      `  Invoke-NativeTimeout 'sc.exe' ("stop $candidate") 2000`,
      `  Invoke-NativeTimeout 'sc.exe' ("delete $candidate") 2000`,
      `  Invoke-NativeTimeout 'schtasks.exe' ("/End /TN $candidate") 2000`,
      `  Invoke-NativeTimeout 'schtasks.exe' ("/Delete /TN $candidate /F") 2000`,
      `}`,
      `Start-Sleep -Milliseconds 1000`,
      `Write-OK "Cleanup done"`,
      ``,
      `# ── Download agent binary ──────────────────────────────────────────────────`,
      `Write-Step "Downloading agent binary..."`,
      `try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}`,
      `try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}`,
      ``,
      `$arch = 'x86_64'`,
      `try { if (-not [Environment]::Is64BitOperatingSystem) { $arch = 'x86' } } catch {`,
      `  if ($env:PROCESSOR_ARCHITECTURE -eq 'x86' -and -not $env:PROCESSOR_ARCHITEW6432) { $arch = 'x86' }`,
      `}`,
      `Write-Host "  Target architecture: $arch" -ForegroundColor Yellow`,
      `$dlUrl = "$Server/api/agent-binary/download?os=windows&arch=$arch"`,
      `$maxRetries = 3`,
      `$retryDelay = 3`,
      `$downloaded = $false`,
      ``,
      `for ($i = 1; $i -le $maxRetries; $i++) {`,
      `  Write-Host "  Attempt $i of $maxRetries..." -ForegroundColor Yellow`,
      `  try {`,
      `    # Prefer WebClient (works everywhere PS 2.0+), fall back to Invoke-WebRequest`,
      `    $wc = New-Object System.Net.WebClient`,
      `    $wc.Headers.Add('User-Agent','Reap3r-Installer/1.0')`,
      `    $wc.DownloadFile($dlUrl, $runExe)`,
      `    $size = (Get-Item $runExe).Length`,
      `    if ($size -lt 10000) { throw "Downloaded file too small ($size bytes)" }`,
      `    Write-OK "Saved: $runExe ($size bytes)"`,
      `    $downloaded = $true`,
      `    break`,
      `  } catch {`,
      `    Write-Host "    Attempt $i failed: $_" -ForegroundColor Yellow`,
      `    Remove-Item $runExe -Force -ErrorAction SilentlyContinue`,
      `    if ($i -lt $maxRetries) {`,
      `      Write-Host "    Waiting $retryDelay seconds before retry..." -ForegroundColor Yellow`,
      `      Start-Sleep -Seconds $retryDelay`,
      `    }`,
      `  }`,
      `}`,
      ``,
      `if (-not $downloaded) {`,
      `  Write-Fail "Failed to download after $maxRetries attempts"`,
      `  Write-Fail "URL: $dlUrl"`,
      `  Write-Fail "Diagnostics:"`,
      `  Write-Fail "  PowerShell version: $($PSVersionTable.PSVersion)"`,
      `  Write-Fail "  TLS protocols: $([System.Net.ServicePointManager]::SecurityProtocol)"`,
      `  try {`,
      `    $wc2 = New-Object System.Net.WebClient`,
      `    $health = $wc2.DownloadString("$Server/health")`,
      `    Write-Fail "  Server reachable: $health"`,
      `  } catch {`,
      `    Write-Fail "  Server unreachable: $_"`,
      `  }`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `# ── Smoke test ────────────────────────────────────────────────────────────────`,
      `Write-Step "Smoke test: agent launch check..."`,
      `try {`,
      `  $verOut = & $runExe --version 2>&1 | Out-String`,
      `  Write-OK "Agent binary is valid ($($verOut.Trim()))"`,
      `} catch {`,
      `  Write-Fail "Agent failed to run: $_"`,
      `  foreach ($lf in $logFiles) {`,
      `    if (Test-Path $lf) {`,
      `      $logFile = $lf`,
      `      Write-Host ""`,
      `      Write-Host "--- Agent log (tail: $lf) ---" -ForegroundColor DarkGray`,
      `      Get-Content $lf -Tail 50 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }`,
      `    }`,
      `  }`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `# ── Install as Windows Service ──────────────────────────────────────────────`,
      `Write-Step "Enrolling + installing agent service..."`,
      `$helpText = ''`,
      `$isCommandCli = $false`,
      `try { $helpText = (& $runExe --help 2>&1 | Out-String) } catch { $helpText = '' }`,
      `# Detect MassVision v2 CLI (subcommands)`,
      `if ($helpText -match '\\[COMMAND\\]' -and $helpText -match 'Commands:') { $isCommandCli = $true }`,
      ``,
      `if ($isCommandCli) {`,
      `  Write-Host "    Using MassVision v2 CLI (subcommands)" -ForegroundColor Yellow`,
      `  $enrollOut = (& $runExe enroll --token "$Token" --server "$Server" 2>&1 | Out-String)`,
      `  if ($LASTEXITCODE -ne 0) {`,
      `    Write-Fail "Enrollment failed (exit $LASTEXITCODE)"`,
      `    Write-Fail $enrollOut.Trim()`,
      `    Read-Host "Press Enter to exit"`,
      `    exit 1`,
      `  }`,
      `  Write-OK "Enrolled"`,
      `  # Try to install as a Windows Service (works for non-UI jobs), but Remote Desktop`,
      `  # screen capture requires an interactive user session on modern Windows.`,
      `  $serviceName = 'MassVisionAgent'`,
      `  $installOk = $false`,
      `  $installOut = ''`,
      `  for ($t = 1; $t -le 3; $t++) {`,
      `    $installOut = (& $runExe install 2>&1 | Out-String)`,
      `    if ($LASTEXITCODE -eq 0) { $installOk = $true; break }`,
      `    Write-Host "    Install attempt $t failed (exit $LASTEXITCODE). Retrying..." -ForegroundColor Yellow`,
      `    Start-Sleep -Seconds 2`,
      `  }`,
      `  if ($installOk) {`,
      `    Write-OK "Service installed/updated"`,
      `  } else {`,
      `    Write-Host "    WARN Service install failed; continuing with interactive task mode (needed for Remote Desktop)." -ForegroundColor Yellow`,
      `    Write-Host ("    " + $installOut.Trim()) -ForegroundColor DarkGray`,
      `    # Ensure Program Files binary exists for the scheduled task`,
      `    try { Copy-Item -Path $runExe -Destination $exePath -Force -ErrorAction SilentlyContinue } catch {}`,
      `  }`,
      ``,
      `  # ── Interactive mode for Remote Desktop (Scheduled Task) ───────────────────`,
      `  # Running as a service (Session 0) often cannot enumerate/capture displays -> "no displays found".`,
      `  # We register a per-user task that runs in the interactive session at logon and start it now.`,
      `  $taskName = 'MassVisionAgentInteractive'`,
      `  try {`,
      `    Write-Step "Configuring interactive mode (Remote Desktop)..."`,
      `    $userId = "$env:USERDOMAIN\\$env:USERNAME"`,
      `    $action = New-ScheduledTaskAction -Execute $exePath`,
      `    $trigger = New-ScheduledTaskTrigger -AtLogOn`,
      `    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType InteractiveToken -RunLevel Highest`,
      `    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null`,
      `    try { Start-ScheduledTask -TaskName $taskName } catch {}`,
      `    Write-OK "Interactive task installed: $taskName ($userId)"`,
      `  } catch {`,
      `    Write-Host "    WARN Could not register interactive task (Remote Desktop may not work): $_" -ForegroundColor Yellow`,
      `  }`,
      `} else {`,
      `  Write-Fail "Unsupported agent binary CLI (expected MassVision v2 command-based CLI)."`,
      `  Write-Fail "Help output:"`,
      `  Write-Host $helpText -ForegroundColor DarkGray`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `# ── Verify service ────────────────────────────────────────────────────────────`,
      `Write-Step "Verifying service status..."`,
      `$q = (sc.exe query $serviceName 2>&1 | Out-String)`,
      `if ($q -notmatch 'RUNNING') {`,
      `  sc.exe start $serviceName > $null 2>&1`,
      `  Start-Sleep -Seconds 2`,
      `  $q = (sc.exe query $serviceName 2>&1 | Out-String)`,
      `}`,
      `if ($q -match 'RUNNING') {`,
      `  Write-OK "Service state: RUNNING"`,
      `} else {`,
      `  Write-Fail "Service not running"`,
      `  Write-Host $q -ForegroundColor DarkGray`,
      `  Write-Host "    Diagnostics: logs are in $dataDirPrimary\\logs" -ForegroundColor Yellow`,
      `  try {`,
      `    Write-Host ""`,
      `    Write-Host "--- Agent status probe ---" -ForegroundColor DarkGray`,
      `    & $exePath status 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }`,
      `  } catch {}`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `# Show first log lines`,
      `Start-Sleep -Seconds 3`,
      `foreach ($lf in $logFiles) {`,
      `  if (Test-Path $lf) {`,
      `    $logFile = $lf`,
      `    Write-Host ""`,
      `    Write-Host "--- Agent log (tail: $lf) ---" -ForegroundColor DarkGray`,
      `    Get-Content $lf -Tail 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }`,
      `    break`,
      `  }`,
      `}`,
      ``,
      `Write-Host ""`,
      `Write-Host "================================================" -ForegroundColor Green`,
      `Write-Host "  Reap3r Agent installed and running!" -ForegroundColor Green`,
      `Write-Host "================================================" -ForegroundColor Green`,
      `Write-Host "Service : $serviceName"`,
      `Write-Host "Binary  : $exePath"`,
      `Write-Host "Server  : $wsUrl"`,
      `Write-Host "Logs    : $logFile"`,
      `Write-Host ""`,
      `Write-Host "Useful commands:"`,
      `Write-Host "  Get-Content '$logFile' -Tail 30 -Wait"`,
      `Write-Host "  Get-Service -Name '$serviceName'"`,
      `Write-Host "  Stop-Service -Name '$serviceName'"`,
      `Write-Host "  Start-Service -Name '$serviceName'"`,
      `Read-Host "Press Enter to close"`,
    ];
    const ps1 = lines.join('\r\n');

    reply.header('Content-Type', 'text/plain; charset=utf-8');
    reply.header('Cache-Control', 'no-store');
    return reply.send(ps1);
  });

  fastify.get('/api/install/macos', async (_request, reply) => {
    reply.header('Content-Type', 'text/plain; charset=utf-8');
    return reply.send(
      [
        '# macOS installer is not packaged yet.',
        '# For now, use Linux install or build the agent from source.',
        '',
      ].join('\n'),
    );
  });
}
