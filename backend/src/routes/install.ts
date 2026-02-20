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
      `$dataDirPrimary = Join-Path $env:ProgramData 'XefiAgent2'`,
      `$dataDirLegacy  = Join-Path $env:ProgramData 'Reap3r'`,
      `$dataDirCandidates = @($dataDirPrimary, $dataDirLegacy)`,
      `$dataDir = $dataDirPrimary`,
      `$logDir  = Join-Path $dataDir 'logs'`,
      `$logFiles = @(`,
      `  (Join-Path $dataDirPrimary 'logs\agent.log'),`,
      `  (Join-Path $dataDirLegacy 'logs\agent.log')`,
      `)`,
      `$configFiles = @(`,
      `  (Join-Path $dataDirPrimary 'agent.conf'),`,
      `  (Join-Path $dataDirLegacy 'agent.conf')`,
      `)`,
      `$serviceCandidates = @('XEFI-Agent-2','MASSVISION-Reap3r-Agent','Reap3rAgent','ReaP3rAgent','xefi-agent-2')`,
      `$serviceName = $serviceCandidates[0]`,
      `$logFile    = $logFiles[0]`,
      ``,
      `Write-Step "Creating directories..."`,
      `New-Item -ItemType Directory -Force -Path $installDir | Out-Null`,
      `foreach ($d in @($dataDirPrimary, $dataDirLegacy, (Join-Path $dataDirPrimary 'logs'), (Join-Path $dataDirLegacy 'logs'))) {`,
      `  New-Item -ItemType Directory -Force -Path $d | Out-Null`,
      `}`,
      `try {`,
      `  $acl = Get-Acl $dataDirPrimary`,
      `  $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow"`,
      `  $acl.SetAccessRule($rule)`,
      `  Set-Acl $dataDirPrimary $acl`,
      `} catch {}`,
      `Write-Step "Removing old config..."`,
      `foreach ($cfg in $configFiles) {`,
      `  if (Test-Path $cfg) {`,
      `    Remove-Item $cfg -Force -ErrorAction SilentlyContinue`,
      `  }`,
      `}`,
      `Write-OK $installDir`,
      ``,
      `Write-Step "Stopping existing agent..."`,
      `# 1. Stop Service if exists`,
      `foreach ($svcName in $serviceCandidates) {`,
      `  if (Get-Service $svcName -ErrorAction SilentlyContinue) {`,
      `    Stop-Service $svcName -Force -ErrorAction SilentlyContinue`,
      `  }`,
      `}`,
      `# 2. Stop Scheduled Task if exists`,
      `foreach ($svcName in $serviceCandidates) {`,
      `  if (Get-ScheduledTask -TaskName $svcName -ErrorAction SilentlyContinue) {`,
      `    Stop-ScheduledTask -TaskName $svcName -ErrorAction SilentlyContinue`,
      `    Unregister-ScheduledTask -TaskName $svcName -Confirm:$false -ErrorAction SilentlyContinue`,
      `  }`,
      `}`,
      `# 3. Kill process`,
      `Stop-Process -Name "reap3r-agent" -Force -ErrorAction SilentlyContinue`,
      `Stop-Process -Name "xefi-agent-2" -Force -ErrorAction SilentlyContinue`,
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
      `Write-Step "Installing agent as Windows Service..."`,
      `$supportsInstallFlag = $false`,
      `$supportsEnrollFlag = $false`,
      `$supportsRunFlag = $false`,
      `$supportsServerFlag = $false`,
      `$supportsTokenFlag = $false`,
      `try {`,
      `  $helpText = (& $exePath --help 2>&1 | Out-String)`,
      `  if ($helpText -match '--install') { $supportsInstallFlag = $true }`,
      `  if ($helpText -match '--enroll') { $supportsEnrollFlag = $true }`,
      `  if ($helpText -match '--run') { $supportsRunFlag = $true }`,
      `  if ($helpText -match '--server') { $supportsServerFlag = $true }`,
      `  if ($helpText -match '--token') { $supportsTokenFlag = $true }`,
      `} catch {}`,
      ``,
      `if ($supportsInstallFlag) {`,
      `  # Preferred path: native installer in modern agent builds`,
      `  $proc = Start-Process -FilePath $exePath -ArgumentList "--install", "--server", "$wsUrl", "--token", "$Token" -Wait -PassThru -NoNewWindow`,
      `  if ($proc.ExitCode -ne 0) {`,
      `    Write-Fail "Agent install command failed with exit code $($proc.ExitCode)"`,
      `    Write-Fail "Check logs at: $logFile"`,
      `    Read-Host "Press Enter to exit"`,
      `    exit 1`,
      `  }`,
      `} else {`,
      `  # Fallback for binaries without --install`,
      `  Write-Host "    WARN --install not supported by this binary, using fallback mode" -ForegroundColor Yellow`,
      `  $serviceArgs = @()`,
      `  if ($supportsRunFlag) { $serviceArgs += '--run' }`,
      `  if ($supportsEnrollFlag) {`,
      `    & $exePath --enroll --server "$wsUrl" --token "$Token"`,
      `    if ($LASTEXITCODE -ne 0) {`,
      `      Write-Fail "Fallback enroll failed with exit code $LASTEXITCODE"`,
      `      Write-Fail "Check logs at: $logFile"`,
      `      Read-Host "Press Enter to exit"`,
      `      exit 1`,
      `    }`,
      `  } elseif ($supportsServerFlag -and $supportsTokenFlag) {`,
      `    Write-Host "    WARN Legacy mode: token will be stored in service binPath for first startup enrollment" -ForegroundColor Yellow`,
      `    $serviceArgs += @('--server', $wsUrl, '--token', $Token)`,
      `  } else {`,
      `    Write-Fail "This agent binary is too old (no --install and no compatible --enroll/--server/--token options)"`,
      `    Read-Host "Press Enter to exit"`,
      `    exit 1`,
      `  }`,
      `  $serviceName = 'XEFI-Agent-2'`,
      `  $quotedArgs = @()`,
      `  foreach ($arg in $serviceArgs) {`,
      `    if ($arg -match '\s') {`,
      `      $quotedArgs += ('"' + $arg.Replace('"','\"') + '"')`,
      `    } else {`,
      `      $quotedArgs += $arg`,
      `    }`,
      `  }`,
      `  $binPath = '"' + $exePath + '"'`,
      `  if ($quotedArgs.Count -gt 0) {`,
      `    $binPath = $binPath + ' ' + ($quotedArgs -join ' ')`,
      `  }`,
      `  & sc.exe delete $serviceName | Out-Null`,
      `  Start-Sleep -Milliseconds 500`,
      `  & sc.exe create $serviceName binPath= $binPath start= auto DisplayName= "XEFI Agent 2" | Out-Null`,
      `  if ($LASTEXITCODE -ne 0) {`,
      `    Write-Fail "Failed to create service ($serviceName) via sc.exe"`,
      `    Read-Host "Press Enter to exit"`,
      `    exit 1`,
      `  }`,
      `  & sc.exe description $serviceName "XEFI Agent 2 remote management service" | Out-Null`,
      `  & sc.exe failure $serviceName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null`,
      `  & sc.exe failureflag $serviceName 1 | Out-Null`,
      `  Start-Service -Name $serviceName -ErrorAction SilentlyContinue`,
      `}`,
      `Write-OK "Service installed/updated"`,
      ``,
      `Write-Step "Verifying service status..."`,
      `$svc = $null`,
      `$started = $false`,
      `for ($i = 0; $i -lt 30; $i++) {`,
      `  $svc = $null`,
      `  foreach ($svcName in $serviceCandidates) {`,
      `    $candidate = Get-Service -Name $svcName -ErrorAction SilentlyContinue`,
      `    if ($candidate) {`,
      `      $svc = $candidate`,
      `      $serviceName = $svcName`,
      `      break`,
      `    }`,
      `  }`,
      `  if ($svc -and $svc.Status -eq 'Running') {`,
      `    $started = $true`,
      `    break`,
      `  }`,
      `  Start-Sleep -Seconds 1`,
      `}`,
      `if (-not $svc) {`,
      `  Write-Fail "No expected service found after installation"` ,
      `  Write-Host "    Checked: $($serviceCandidates -join ', ')" -ForegroundColor Yellow`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      `if ($started) {`,
      `  Write-OK "Service state: $($svc.Status)"`,
      `} else {`,
      `  Write-Fail "Service state: $($svc.Status) (expected Running)"`,
      `  Write-Host "    Collecting diagnostics..." -ForegroundColor Yellow`,
      `  foreach ($lf in $logFiles) {`,
      `    if (Test-Path $lf) {`,
      `      $logFile = $lf`,
      `      Write-Host ""`,
      `      Write-Host "--- Agent log (tail: $lf) ---" -ForegroundColor DarkGray`,
      `      Get-Content $lf -Tail 80 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }`,
      `    }`,
      `  }`,
      `  try {`,
      `    Write-Host ""`,
      `    Write-Host "--- Agent status probe ---" -ForegroundColor DarkGray`,
      `    & $exePath --status | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }`,
      `  } catch {}`,
      `  Read-Host "Press Enter to exit"`,
      `  exit 1`,
      `}`,
      ``,
      `# Try to show first log lines`,
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
