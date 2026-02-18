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
    return reply.send(script);
  });

  fastify.get('/api/install/windows', async (_request, reply) => {
    const q = _request.query as any;
    const token = String(q.token ?? '');
    const base = publicBaseUrl(_request);

    // Installs a Windows Service; must be run from an elevated PowerShell.
    const ps1 = `param(
  [string]$Token  = "${token}",
  [string]$Server = "${base}"
)

$ErrorActionPreference = "Stop"
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13

function Write-Step([string]$msg) { Write-Host \`\`n"[reap3r] $msg" -ForegroundColor Cyan }
function Write-OK([string]$msg)   { Write-Host "    OK  $msg" -ForegroundColor Green }
function Write-Fail([string]$msg) { Write-Host "    ERR $msg" -ForegroundColor Red }

# ── Admin check ──────────────────────────────────────────────────────────────
$wp = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Fail "Please run PowerShell as Administrator (right-click → Run as administrator)."
  Read-Host "Press Enter to exit"
  exit 1
}

if ([string]::IsNullOrWhiteSpace($Token)) {
  Write-Fail "Missing enrollment token. Provide ?token=... in the URL."
  Read-Host "Press Enter to exit"
  exit 1
}

$Server = $Server.TrimEnd('/')
if (-not ($Server -match '^https?://')) {
  Write-Fail "Server URL must start with https:// or http://. Got: $Server"
  Read-Host "Press Enter to exit"
  exit 1
}

# Convert http(s):// → ws(s)://
$wsUrl = ($Server -replace '^http://', 'ws://') -replace '^https://', 'wss://'
$wsUrl = "$wsUrl/ws/agent"

$installDir = Join-Path $env:ProgramFiles 'MASSVISION\\Reap3r'
$exePath    = Join-Path $installDir 'reap3r-agent.exe'
$dataDir    = Join-Path $env:ProgramData 'Reap3r'
$logDir     = Join-Path $dataDir 'logs'
$svcName    = 'MASSVISION-Reap3r-Agent'

Write-Step "Creating directories..."
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $dataDir    | Out-Null
New-Item -ItemType Directory -Force -Path $logDir     | Out-Null
Write-OK $installDir

Write-Step "Downloading agent binary from $Server ..."
try {
  Invoke-WebRequest -UseBasicParsing \`
    -Uri "$Server/api/agent-binary/download?os=windows&arch=x86_64" \`
    -OutFile $exePath
  $size = (Get-Item $exePath).Length
  Write-OK "Saved to $exePath ($size bytes)"
} catch {
  Write-Fail "Download failed: $_"
  Write-Fail "Make sure you can reach $Server from this machine."
  Read-Host "Press Enter to exit"
  exit 1
}

Write-Step "Writing agent config ($dataDir\\agent.conf)..."
$agentConf = @{
  agent_id   = ""
  hmac_key   = ""
  server     = $wsUrl
  enrolled_at = 0
} | ConvertTo-Json
Set-Content -Path "$dataDir\\agent.conf" -Value $agentConf -Encoding UTF8
Write-OK "Config written (will be populated on first enrollment)"

Write-Step "Installing Windows service '$svcName' ..."
$existingSvc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existingSvc) {
  try { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue } catch {}
  sc.exe delete $svcName | Out-Null
  Start-Sleep -Seconds 2
}

# The binary runs in service mode: REAP3R_SERVICE_MODE=1 triggers service dispatcher.
# Pass --server and --token as arguments so first-run enrollment works.
# After enrollment, agent.conf is written and args are no longer needed.
$bin = "\`"$exePath\`" --server \`"$wsUrl\`" --token \`"$Token\`""
New-Service -Name $svcName \`
  -BinaryPathName $bin \`
  -DisplayName "MASSVISION Reap3r Agent" \`
  -Description "MASSVISION Reap3r remote-management agent" \`
  -StartupType Automatic | Out-Null

# Set environment variable for service mode in registry
$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$svcName"
New-ItemProperty -Path $regPath -Name "Environment" \`
  -Value @("REAP3R_SERVICE_MODE=1", "REAP3R_LOG_FILE=$logDir\\agent.log") \`
  -PropertyType MultiString -Force | Out-Null

# Auto-restart on failure (3 times, every 5s)
sc.exe failure $svcName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
Write-OK "Service created"

Write-Step "Starting service..."
try {
  Start-Service -Name $svcName
  Start-Sleep -Seconds 3
  $svc = Get-Service -Name $svcName
  if ($svc.Status -eq 'Running') {
    Write-OK "Status: $($svc.Status)"
  } else {
    Write-Fail "Service status: $($svc.Status) (expected Running)"
    Write-Host "    Check logs at: $logDir\\agent.log" -ForegroundColor Yellow
    Write-Host "    Or run: Get-WinEvent -LogName System | Where-Object {\\$_.Message -like '*$svcName*'} | Select-Object -First 10" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
  }
} catch {
  Write-Fail "Failed to start service: $_"
  Write-Host "    Check logs at: $logDir\\agent.log" -ForegroundColor Yellow
  Read-Host "Press Enter to exit"
  exit 1
}

Write-Host \`\`n"═══════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Reap3r Agent installed and running!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Green
Write-Host "Service : $svcName"
Write-Host "Binary  : $exePath"
Write-Host "Server  : $wsUrl"
Write-Host "Logs    : $logDir\\agent.log"
Write-Host ""
Write-Host "To check logs:"
Write-Host "  Get-Content '$logDir\\agent.log' -Tail 30"
Write-Host ""
Write-Host "To check service status:"
Write-Host "  Get-Service $svcName"
Read-Host \`\`n"Press Enter to close"
`;

    reply.header('Content-Type', 'text/plain; charset=utf-8');
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
