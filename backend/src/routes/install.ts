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
  [string]$Token = "${token}",
  [string]$Server = "${base}"
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
  $wp = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run PowerShell as Administrator."
    exit 1
  }
}

Assert-Admin

if ([string]::IsNullOrWhiteSpace($Token)) {
  Write-Error "Missing token. Provide ?token=... or -Token ..."
  exit 1
}

$Server = $Server.TrimEnd('/')
$wsBase = $Server -replace '^http(s?)://', 'ws$1://'
$wsUrl = "$wsBase/ws/agent"

$installDir = Join-Path $env:ProgramFiles 'MASSVISION\\Reap3r'
$exePath = Join-Path $installDir 'reap3r-agent.exe'
$svcName = 'MASSVISION-Reap3r-Agent'

New-Item -ItemType Directory -Force -Path $installDir | Out-Null

Write-Host "[reap3r] Downloading agent..." -ForegroundColor Cyan
Invoke-WebRequest -UseBasicParsing -Uri "$Server/api/agent-binary/download?os=windows&arch=x86_64" -OutFile $exePath

Write-Host "[reap3r] Installing service $svcName" -ForegroundColor Cyan
if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
  try { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue } catch {}
  sc.exe delete $svcName | Out-Null 2>$null
  Start-Sleep -Seconds 1
}

# Important: the full binary path (exe + args) must be stored as ONE value, otherwise the service will start without
# args and the agent won't be able to connect/enroll.
$bin = '"' + $exePath + '" --server "' + $wsUrl + '" --token "' + $Token + '"'
New-Service -Name $svcName -BinaryPathName $bin -DisplayName $svcName -StartupType Automatic | Out-Null
sc.exe failure $svcName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null

Write-Host "[reap3r] Service config:" -ForegroundColor Cyan
sc.exe qc $svcName | Select-String 'BINARY_PATH_NAME' | ForEach-Object { Write-Host $_.Line }

Write-Host "[reap3r] Starting service..." -ForegroundColor Cyan
Start-Service -Name $svcName

Write-Host "[reap3r] Done." -ForegroundColor Green
Write-Host "Service: $svcName"
Write-Host "Binary:  $exePath"
Write-Host "Server:  $wsUrl"
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
