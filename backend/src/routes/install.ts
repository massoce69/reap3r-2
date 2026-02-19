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

    // Build the PS1 using array join to avoid ALL backtick / escaping issues in TS template strings.
    // Each entry is one line of the PowerShell script.
    const lines: string[] = [
      `param(`,
      `  [string]$Token  = "${token}",`,
      `  [string]$Server = "${base}"`,
      `)`,
      ``,
      `$ErrorActionPreference = "Stop"`,
      `try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}`,
      ``,
      `function Write-Step([string]$msg) { Write-Host "" ; Write-Host "[reap3r] $msg" -ForegroundColor Cyan }`,
      `function Write-OK([string]$msg)   { Write-Host "    OK  $msg" -ForegroundColor Green }`,
      `function Write-Fail([string]$msg) { Write-Host "    ERR $msg" -ForegroundColor Red }`,
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
      `$wsUrl = "$wsUrl/ws/agent"`,
      ``,
      `$installDir = Join-Path $env:ProgramFiles 'MASSVISION' | Join-Path -ChildPath 'Reap3r'`,
      `$exePath    = Join-Path $installDir 'reap3r-agent.exe'`,
      `$dataDir    = Join-Path $env:ProgramData 'Reap3r'`,
      `$logDir     = Join-Path $dataDir 'logs'`,
      `$serviceName = 'MASSVISION-Reap3r-Agent'`,
      `$logFile    = Join-Path $logDir 'agent.log'`,
      `$configFile = Join-Path $dataDir 'agent.conf'`,
      ``,
      `Write-Step "Creating directories..."`,
      `New-Item -ItemType Directory -Force -Path $installDir | Out-Null`,
      `New-Item -ItemType Directory -Force -Path $dataDir    | Out-Null`,
      `New-Item -ItemType Directory -Force -Path $logDir     | Out-Null`,
      `try {`,
      `  $acl = Get-Acl $dataDir`,
      `  $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow"`,
      `  $acl.SetAccessRule($rule)`,
      `  Set-Acl $dataDir $acl`,
      `} catch {}`,
      `if (Test-Path $configFile) {`,
      `  Write-Step "Removing old config..."`,
      `  Remove-Item $configFile -Force -ErrorAction SilentlyContinue`,
      `}`,
      `Write-OK $installDir`,
      ``,
      `Write-Step "Stopping existing agent..."`,
      `# 1. Stop Service if exists`,
      `if (Get-Service $serviceName -ErrorAction SilentlyContinue) {`,
      `  Stop-Service $serviceName -Force -ErrorAction SilentlyContinue`,
      `}`,
      `# 2. Stop Scheduled Task if exists`,
      `if (Get-ScheduledTask -TaskName $serviceName -ErrorAction SilentlyContinue) {`,
      `  Stop-ScheduledTask -TaskName $serviceName -ErrorAction SilentlyContinue`,
      `  Unregister-ScheduledTask -TaskName $serviceName -Confirm:$false -ErrorAction SilentlyContinue`,
      `}`,
      `# 3. Kill process`,
      `Stop-Process -Name "reap3r-agent" -Force -ErrorAction SilentlyContinue`,
      `Start-Sleep -Seconds 1`,
      ``,
      `Write-Step "Downloading agent binary..."`,
      `# Fix SSL/TLS for older PowerShell (3072 = Tls12, avoids enum name issues)`,
      `try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}`,
      `[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { \$true }`,
      ``,
      `$dlUrl = "$Server/api/agent-binary/download?os=windows&arch=x86_64"`,
      `$maxRetries = 3`,
      `$retryDelay = 2`,
      `$downloaded = $false`,
      ``,
      `for ($i = 1; $i -le $maxRetries; $i++) {`,
      `  try {`,
      `    Write-Host "  Attempt $i of $maxRetries..." -ForegroundColor Yellow`,
      `    # Use Invoke-WebRequest; -SkipCertificateCheck only works on PS 6+`,
      `    if ($PSVersionTable.PSVersion.Major -ge 6) {`,
      `      Invoke-WebRequest -Uri $dlUrl -OutFile $exePath -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop`,
      `    } else {`,
      `      # PS 5 and earlier: rely on ServicePointManager callback set above`,
      `      Invoke-WebRequest -Uri $dlUrl -OutFile $exePath -UseBasicParsing -ErrorAction Stop`,
      `    }`,
      `    $size = (Get-Item $exePath).Length`,
      `    Write-OK "Saved: $exePath ($size bytes)"`,
      `    $downloaded = $true`,
      `    break`,
      `  } catch {`,
      `    Write-Host "    Retry $i failed: $_" -ForegroundColor Yellow`,
      `    Remove-Item $exePath -ErrorAction SilentlyContinue`,
      `    if ($i -lt $maxRetries) {`,
      `      Write-Host "    Waiting \${retryDelay}s before retry..." -ForegroundColor Yellow`,
      `      Start-Sleep -Seconds $retryDelay`,
      `    }`,
      `  }`,
      `}`,
      ``,
      `if (-not $downloaded) {`,

      `  Write-Fail "Failed to download after $maxRetries attempts"`,
      `  Write-Fail "URL: $dlUrl"`,
      `  Write-Fail ""`,
      `  Write-Fail "Diagnostics:"`,
      `  Write-Fail "  - PowerShell: $($PSVersionTable.PSVersion)"`,
      `  Write-Fail "  - TLS: $([System.Net.ServicePointManager]::SecurityProtocol)"`,
      `  try {`,
      `    if ($PSVersionTable.PSVersion.Major -ge 6) {`,
      `      $test = Invoke-WebRequest -Uri "$Server/health" -SkipCertificateCheck -UseBasicParsing -TimeoutSec 5`,
      `    } else {`,
      `      $test = Invoke-WebRequest -Uri "$Server/health" -UseBasicParsing -TimeoutSec 5`,
      `    }`,
      `    Write-Fail "  - Server reachable: HTTP $($test.StatusCode)"`,
      `  } catch {`,
      `    Write-Fail "  - Server unreachable: $_"`,
      `  }`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `Write-Step "Smoke test: agent launch check..."`,
      `try {`,
      `  & $exePath --version | Out-Null`,
      `  Write-OK "Agent binary is valid"`,
      `} catch {`,
      `  Write-Fail "Agent failed to run: $_"`,
      `  if (Test-Path $logFile) {`,
      `    Write-Host ""`,
      `    Write-Host "--- Agent log (tail) ---" -ForegroundColor DarkGray`,
      `    Get-Content $logFile -Tail 50 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }`,
      `  }`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `# ── Install as Windows Service ──────────────────────────────────────────────`,
      `Write-Step "Installing agent as Windows Service..."`,
      `# Run with --install (handles sc create/config, Recovery, EventLog, etc.)`,
      `$proc = Start-Process -FilePath $exePath -ArgumentList "--install", "--server", "$wsUrl", "--token", "$Token" -Wait -PassThru -NoNewWindow`,
      `if ($proc.ExitCode -ne 0) {`,
      `  Write-Fail "Agent install command failed with exit code $($proc.ExitCode)"`,
      `  Write-Fail "Check logs at: $logFile"`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      `Write-OK "Service installed/updated"`,
      ``,
      `Write-Step "Verifying service status..."`,
      `Start-Sleep -Seconds 2`,
      `$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue`,
      `if ($svc.Status -eq 'Running') {`,
      `  Write-OK "Service state: $($svc.Status)"`,
      `} else {`,
      `  Write-Fail "Service state: $($svc.Status) (expected Running)"`,
      `  Write-Host "    Check logs: $logFile" -ForegroundColor Yellow`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `# Try to show first log lines`,
      `Start-Sleep -Seconds 3`,
      `if (Test-Path $logFile) {`,
      `  Write-Host ""`,
      `  Write-Host "--- Agent log (first lines) ---" -ForegroundColor DarkGray`,
      `  Get-Content $logFile -Tail 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }`,
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
