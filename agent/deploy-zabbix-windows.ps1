#Requires -Version 3.0
<#
.SYNOPSIS
    Reap3r Agent - Zabbix-triggered Windows installer

.DESCRIPTION
    1. Checks if the agent is already installed and running
    2. Downloads the latest reap3r-agent.exe from the management server
    3. Runs one-shot enrollment + service install using native --install
    4. Verifies service startup and reports useful log locations
#>
param(
    [string]$ServerUrl   = $env:REAP3R_SERVER,
    [string]$Token       = $env:REAP3R_TOKEN,
    [string]$DownloadUrl = $env:REAP3R_DLURL,
    [switch]$Force       = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -- Constants -----------------------------------------------------------------
$PRIMARY_SERVICE_NAME = "XEFI-Agent-2"
$SERVICE_CANDIDATES = @(
    $PRIMARY_SERVICE_NAME,
    "MASSVISION-Reap3r-Agent",
    "Reap3rAgent",
    "ReaP3rAgent",
    "xefi-agent-2"
) | Select-Object -Unique

$DEFAULT_INSTALL_DIR = "C:\Program Files\Reap3r"
$LEGACY_INSTALL_DIRS = @(
    "C:\ProgramData\Reap3r",
    "C:\Program Files\Reap3r Agent"
)

$PRIMARY_DATA_DIR = Join-Path $env:ProgramData "XefiAgent2"
$LEGACY_DATA_DIR = Join-Path $env:ProgramData "Reap3r"
$AGENT_LOG_CANDIDATES = @(
    (Join-Path $PRIMARY_DATA_DIR "logs\agent.log"),
    (Join-Path $LEGACY_DATA_DIR "logs\agent.log")
)

function Resolve-InstallDir {
    $dirs = @($DEFAULT_INSTALL_DIR) + $LEGACY_INSTALL_DIRS
    foreach ($dir in $dirs) {
        $candidate = Join-Path $dir "reap3r-agent.exe"
        if (Test-Path $candidate) { return $dir }
    }
    return $DEFAULT_INSTALL_DIR
}

$INSTALL_DIR = Resolve-InstallDir
$EXE_PATH = Join-Path $INSTALL_DIR "reap3r-agent.exe"
$LOG_FILE = Join-Path $INSTALL_DIR "install.log"

# -- Helpers -------------------------------------------------------------------
function Log {
    param([string]$Level, [string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Write-Host $line
    $null = New-Item -ItemType Directory -Path $INSTALL_DIR -Force -ErrorAction SilentlyContinue
    Add-Content -Path $LOG_FILE -Value $line -ErrorAction SilentlyContinue
}

function Die {
    param([string]$Message)
    Log "ERROR" $Message
    exit 1
}

function Get-AnyService {
    foreach ($name in $SERVICE_CANDIDATES) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) { return $svc }
    }
    return $null
}

function Get-RunningService {
    foreach ($name in $SERVICE_CANDIDATES) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { return $svc }
    }
    return $null
}

function Remove-AgentServices {
    foreach ($name in $SERVICE_CANDIDATES) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        Log "INFO" "Stopping existing service: $name"
        Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        & sc.exe delete $name 2>&1 | Out-Null
    }
}

function Resolve-AgentLogFile {
    foreach ($path in $AGENT_LOG_CANDIDATES) {
        if (Test-Path $path) { return $path }
    }
    return ""
}

# -- Elevation check ------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator
)
if (-not $isAdmin) { Die "Must run as Administrator / SYSTEM" }

# -- Parameter validation -------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($ServerUrl)) { Die "REAP3R_SERVER not set. Pass -ServerUrl or set env:REAP3R_SERVER" }
if ([string]::IsNullOrWhiteSpace($Token)) { Die "REAP3R_TOKEN not set. Pass -Token or set env:REAP3R_TOKEN" }

$ServerUrl = $ServerUrl.Trim()
if ($ServerUrl -notmatch '^wss?://') {
    Die "Server URL must start with ws:// or wss:// (got: $ServerUrl)"
}

# Derive HTTP base from WebSocket URL
$HttpBase = $ServerUrl -replace '^wss://', 'https://' -replace '^ws://', 'http://' -replace '/ws/agent$', ''

if ([string]::IsNullOrWhiteSpace($DownloadUrl)) {
    $DownloadUrl = "$HttpBase/api/agent-binary/download?os=windows&arch=x86_64"
}

Log "INFO" "===== Reap3r Agent Zabbix Deploy ====="
Log "INFO" "Host      : $env:COMPUTERNAME"
Log "INFO" "Server    : $ServerUrl"
Log "INFO" "DL URL    : $DownloadUrl"
Log "INFO" "Install   : $EXE_PATH"

# -- Check if already installed and healthy ------------------------------------
if (-not $Force) {
    $existingService = Get-RunningService
    if ($existingService -and (Test-Path $EXE_PATH)) {
        $healthUrl = "$HttpBase/api/health"
        try {
            $null = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            Log "INFO" "Agent already running ($($existingService.Name)) and backend reachable. Use -Force to reinstall."
            exit 0
        } catch {
            Log "WARN" "Service is running but backend is unreachable - continuing install"
        }
    }
}

# -- Detect architecture --------------------------------------------------------
$arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
$DownloadUrl = $DownloadUrl -replace "arch=(amd64|x64|x86_64|x86)", "arch=$arch"
Log "INFO" "Arch      : $arch"

# -- Stop existing service if present ------------------------------------------
Remove-AgentServices
Start-Sleep -Seconds 1

# -- Create install directory ---------------------------------------------------
$null = New-Item -ItemType Directory -Path $INSTALL_DIR -Force
Log "INFO" "Install directory: $INSTALL_DIR"

# Secure the install directory (SYSTEM + Administrators only)
try {
    icacls $INSTALL_DIR /inheritance:r | Out-Null
    icacls $INSTALL_DIR /grant:r "SYSTEM:(OI)(CI)F" 2>&1 | Out-Null
    icacls $INSTALL_DIR /grant:r "Administrators:(OI)(CI)F" 2>&1 | Out-Null
} catch {
    Log "WARN" "Could not restrict directory permissions: $_"
}

# -- Download binary ------------------------------------------------------------
Log "INFO" "Downloading from $DownloadUrl ..."
$tmpPath = Join-Path $INSTALL_DIR "reap3r-agent-new.exe"

try {
    if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
        Start-BitsTransfer -Source $DownloadUrl -Destination $tmpPath -ErrorAction Stop
    } else {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add("User-Agent", "Reap3r-Installer/1.0 Windows/$arch")
        $wc.DownloadFile($DownloadUrl, $tmpPath)
    }
    $size = (Get-Item $tmpPath).Length
    Log "INFO" "Downloaded: $size bytes"
} catch {
    Die "Download failed: $_"
}

$downloadedSize = (Get-Item $tmpPath).Length
if ($downloadedSize -lt 100000) {
    Die "Downloaded file too small ($downloadedSize bytes) - likely an error page"
}

# -- Move binary into place -----------------------------------------------------
if (Test-Path $EXE_PATH) { Remove-Item $EXE_PATH -Force }
Move-Item $tmpPath $EXE_PATH -Force
Log "INFO" "Binary installed: $EXE_PATH"

# -- Enroll + install service in one step --------------------------------------
Log "INFO" "Running native install (--install --server --token)..."
$installArgs = @(
    "--install",
    "--server", $ServerUrl,
    "--token", $Token
)
$proc = Start-Process -FilePath $EXE_PATH -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) {
    Die "Install/enroll failed (exit $($proc.ExitCode)) - check $LOG_FILE"
}
Log "INFO" "Install/enroll command completed"

# Detect which service name is active after install.
$activeService = $null
for ($i = 0; $i -lt 20; $i++) {
    $activeService = Get-AnyService
    if ($activeService) { break }
    Start-Sleep -Seconds 1
}
if (-not $activeService) {
    Die "No expected agent service found after install. Checked: $($SERVICE_CANDIDATES -join ', ')"
}

# -- Configure service recovery -------------------------------------------------
Log "INFO" "Configuring service recovery policy for $($activeService.Name)..."
& sc.exe failure $activeService.Name reset=86400 actions=restart/5000/restart/15000/restart/30000 | Out-Null
& sc.exe failureflag $activeService.Name 1 | Out-Null

# -- Start + wait for service ---------------------------------------------------
if ($activeService.Status -ne "Running") {
    Log "INFO" "Starting service $($activeService.Name)..."
    Start-Service -Name $activeService.Name -ErrorAction SilentlyContinue
}

$running = $null
for ($i = 0; $i -lt 20; $i++) {
    $running = Get-RunningService
    if ($running) { break }
    Start-Sleep -Seconds 1
}

if ($running) {
    $agentLog = Resolve-AgentLogFile
    Log "INFO" "SUCCESS: Service $($running.Name) is RUNNING"
    if ($agentLog) {
        Log "INFO" "Agent log: $agentLog"
    } else {
        Log "INFO" "Agent log not found yet (expected under $PRIMARY_DATA_DIR\\logs)"
    }
    Log "INFO" "===== Deploy complete ====="
    exit 0
}

$svc = Get-AnyService
$status = if ($svc) { $svc.Status } else { "NOT FOUND" }
Die "Service status after start: $status - check $LOG_FILE"
