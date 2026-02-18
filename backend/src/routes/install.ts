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
      `[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13`,
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
      `$taskName   = 'MASSVISION-Reap3r-Agent'`,
      `$logFile    = Join-Path $logDir 'agent.log'`,
      ``,
      `Write-Step "Creating directories..."`,
      `New-Item -ItemType Directory -Force -Path $installDir | Out-Null`,
      `New-Item -ItemType Directory -Force -Path $dataDir    | Out-Null`,
      `New-Item -ItemType Directory -Force -Path $logDir     | Out-Null`,
      `Write-OK $installDir`,
      ``,
      `Write-Step "Downloading agent binary..."`,
      `# Use Invoke-WebRequest with better error handling and cert bypass`,
      `$dlUrl = "$Server/api/agent-binary/download?os=windows&arch=x86_64"`,
      `$maxRetries = 3`,
      `$retryDelay = 2`,
      `$downloaded = $false`,
      ``,
      `for ($i = 1; $i -le $maxRetries; $i++) {`,
      `  try {`,
      `    Write-Host "  Attempt $i of $maxRetries..." -ForegroundColor Yellow`,
      `    # Use Invoke-WebRequest with -SkipCertificateCheck (works on PS 6+)`,
      `    $params = @{`,
      `      Uri = $dlUrl`,
      `      OutFile = $exePath`,
      `      UseBasicParsing = $true`,
      `      ErrorAction = 'Stop'`,
      `    }`,
      `    # Add -SkipCertificateCheck if PowerShell version supports it`,
      `    if ($PSVersionTable.PSVersion.Major -ge 6) {`,
      `      $params['SkipCertificateCheck'] = $true`,
      `    } else {`,
      `      # For PS 5 and earlier, bypass via ServicePointManager`,
      `      [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { \$true }`,
      `    }`,
      `    Invoke-WebRequest @params`,
      `    $size = (Get-Item $exePath).Length`,
      `    Write-OK "Saved: $exePath ($size bytes)"`,
      `    $downloaded = $true`,
      `    break`,
      `  } catch {`,
      `    Write-Host "    Retry $i failed: $_" -ForegroundColor Yellow`,
      `    # Clean up partial download`,
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
      `  Write-Fail "  - PowerShell version: $($PSVersionTable.PSVersion)"`,
      `  try {`,
      `    $test = Invoke-WebRequest -Uri $Server/health -SkipCertificateCheck -UseBasicParsing -TimeoutSec 5`,
      `    Write-Fail "  - Server is reachable (" $test.StatusCode ")"`,
      `  } catch {`,
      `    Write-Fail "  - Server NOT reachable: $_"`,
      `  }`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `Write-Step "Smoke test: enroll + heartbeat (12s)..."`,
      `try {`,
      `  & $exePath --server "$wsUrl" --token "$Token" --run-for-secs 12 | Out-Null`,
      `  Write-OK "Agent ran (check logs for Enrolled OK / Heartbeat sent)"`,
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
      `# ── Remove existing scheduled task if present ────────────────────────────────`,
      `Write-Step "Registering scheduled task '$taskName'..."`,
      `$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue`,
      `if ($existing) {`,
      `  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue`,
      `  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false`,
      `  Start-Sleep -Seconds 1`,
      `}`,
      ``,
      `# Use XML to define the task precisely — avoids escaping issues with New-ScheduledTask`,
      `$taskXml = @"`,
      `<?xml version="1.0" encoding="UTF-16"?>`,
      `<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">`,
      `  <RegistrationInfo><Description>MASSVISION Reap3r remote-management agent</Description></RegistrationInfo>`,
      `  <Triggers>`,
      `    <BootTrigger><Enabled>true</Enabled></BootTrigger>`,
      `  </Triggers>`,
      `  <Principals>`,
      `    <Principal id="Author">`,
      `      <UserId>S-1-5-18</UserId>`,
      `      <RunLevel>HighestAvailable</RunLevel>`,
      `    </Principal>`,
      `  </Principals>`,
      `  <Settings>`,
      `    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>`,
      `    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>`,
      `    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>`,
      `    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>`,
      `    <RestartOnFailure>`,
      `      <Interval>PT1M</Interval>`,
      `      <Count>999</Count>`,
      `    </RestartOnFailure>`,
      `    <Enabled>true</Enabled>`,
      `  </Settings>`,
      `  <Actions Context="Author">`,
      `    <Exec>`,
      `      <Command>$exePath</Command>`,
      `      <Arguments>--server "$wsUrl" --token "$Token"</Arguments>`,
      `    </Exec>`,
      `  </Actions>`,
      `</Task>`,
      `"@`,
      ``,
      `Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force | Out-Null`,
      `Write-OK "Task registered (runs at boot as SYSTEM, restarts every 30s on failure)"`,
      ``,
      `Write-Step "Starting agent now..."`,
      `Start-ScheduledTask -TaskName $taskName`,
      `Start-Sleep -Seconds 4`,
      ``,
      `$state = (Get-ScheduledTask -TaskName $taskName).State`,
      `if ($state -eq 'Running') {`,
      `  Write-OK "Task state: $state"`,
      `} else {`,
      `  Write-Fail "Task state: $state (expected Running)"`,
      `  Write-Host "    Check logs: $logFile" -ForegroundColor Yellow`,
      `  Write-Host "    Or: Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational | Select-Object -First 20" -ForegroundColor Yellow`,
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
      `Write-Host "Task    : $taskName"`,
      `Write-Host "Binary  : $exePath"`,
      `Write-Host "Server  : $wsUrl"`,
      `Write-Host "Logs    : $logFile"`,
      `Write-Host ""`,
      `Write-Host "Useful commands:"`,
      `Write-Host "  Get-Content '$logFile' -Tail 30 -Wait"`,
      `Write-Host "  Get-ScheduledTask -TaskName '$taskName'"`,
      `Write-Host "  Stop-ScheduledTask -TaskName '$taskName'"`,
      `Write-Host "  Start-ScheduledTask -TaskName '$taskName'"`,
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
