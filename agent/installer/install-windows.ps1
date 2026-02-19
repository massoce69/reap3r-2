#Requires -RunAsAdministrator
<#
.SYNOPSIS
    MASSVISION Reap3r Agent — PowerShell installer (fallback / CI use)
.DESCRIPTION
    Installs reap3r-agent.exe as a Windows service.
    Run as Administrator.
.PARAMETER Server
    WebSocket server URL, e.g. wss://reap3r.example.com/ws/agent
.PARAMETER Token
    One-time enrollment token
.PARAMETER ExeSource
    Path to local reap3r-agent.exe, OR a URL to download it from.
    Default: looks for reap3r-agent.exe next to this script.
.PARAMETER Uninstall
    Remove the service and files.
.EXAMPLE
    .\install-windows.ps1 -Server wss://reap3r.example.com/ws/agent -Token abc123
.EXAMPLE
    .\install-windows.ps1 -Server wss://... -Token abc123 -ExeSource https://releases.example.com/reap3r-agent.exe
.EXAMPLE
    .\install-windows.ps1 -Uninstall
#>
param(
    [string]$Server   = "",
    [string]$Token    = "",
    [string]$ExeSource = "",
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName   = "Reap3rAgent"
$LegacyServiceNames = @("MASSVISION-Reap3r-Agent", "ReaP3rAgent")
$DisplayName   = "Reap3r Agent (MASSVISION)"
$Description   = "MASSVISION Reap3r remote-management agent"
$InstallDir    = "C:\Program Files\Reap3r Agent"
$DataDir       = "C:\ProgramData\Reap3r"
$LogDir        = "$DataDir\logs"
$ConfigFile    = "$DataDir\agent.conf"
$ExeDest       = "$InstallDir\reap3r-agent.exe"

function Write-Step([string]$msg) {
    Write-Host "`n[+] $msg" -ForegroundColor Cyan
}
function Write-OK([string]$msg) {
    Write-Host "    [OK] $msg" -ForegroundColor Green
}
function Write-Warn([string]$msg) {
    Write-Host "    [WARN] $msg" -ForegroundColor Yellow
}
function Write-Fail([string]$msg) {
    Write-Host "    [FAIL] $msg" -ForegroundColor Red
}

# ─── UNINSTALL ────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Write-Step "Uninstalling Reap3r Agent..."
    foreach ($svcName in (@($ServiceName) + $LegacyServiceNames | Select-Object -Unique)) {
        try { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue } catch {}
        try { sc.exe delete $svcName | Out-Null } catch {}
    }

    if (Test-Path $ExeDest)  { Remove-Item $ExeDest -Force }
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }

    Write-OK "Service removed."
    Write-Warn "Config/logs in $DataDir were kept. Remove manually if desired."
    exit 0
}

# ─── VALIDATION ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "  MASSVISION Reap3r Agent — Windows Installer"           -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Magenta

if (-not $Server) {
    $Server = Read-Host "  Enter Server URL (e.g. wss://YOUR_SERVER/ws/agent)"
}
if (-not $Token) {
    $Token = Read-Host "  Enter Enrollment Token"
}

if (-not ($Server -match '^wss?://')) {
    Write-Fail "Server URL must start with ws:// or wss://. Got: $Server"
    exit 1
}
if (-not $Token) {
    Write-Fail "Enrollment token is required."
    exit 1
}

# ─── LOCATE / DOWNLOAD EXE ───────────────────────────────────────────────────
Write-Step "Locating reap3r-agent.exe..."

$ExeLocal = ""
if ($ExeSource -match '^https?://') {
    # Download from URL
    $TmpExe = "$env:TEMP\reap3r-agent.exe"
    Write-Host "    Downloading from $ExeSource ..."
    try {
        Invoke-WebRequest -Uri $ExeSource -OutFile $TmpExe -UseBasicParsing
        $ExeLocal = $TmpExe
        Write-OK "Downloaded to $TmpExe"
    } catch {
        Write-Fail "Download failed: $_"
        exit 1
    }
} elseif ($ExeSource -and (Test-Path $ExeSource)) {
    $ExeLocal = $ExeSource
    Write-OK "Using provided path: $ExeSource"
} else {
    # Look next to script
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidates = @(
        "$ScriptDir\reap3r-agent.exe",
        "$ScriptDir\..\target\release\reap3r-agent.exe",
        "$ScriptDir\..\target\x86_64-pc-windows-msvc\release\reap3r-agent.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $ExeLocal = (Resolve-Path $c).Path; break }
    }
    if (-not $ExeLocal) {
        Write-Fail "Cannot find reap3r-agent.exe. Pass -ExeSource <path> or <url>."
        exit 1
    }
    Write-OK "Found: $ExeLocal"
}

# ─── STOP EXISTING SERVICE ───────────────────────────────────────────────────
Write-Step "Stopping existing service (if any)..."
$removedAny = $false
foreach ($svcName in (@($ServiceName) + $LegacyServiceNames | Select-Object -Unique)) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    sc.exe delete $svcName | Out-Null
    Start-Sleep -Seconds 1
    Write-OK "Old service removed: $svcName"
    $removedAny = $true
}
if (-not $removedAny) {
    Write-OK "No existing service"
}

# ─── CREATE DIRECTORIES ──────────────────────────────────────────────────────
Write-Step "Creating directories..."
foreach ($d in @($InstallDir, $DataDir, $LogDir)) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    Write-OK $d
}

# ─── COPY BINARY ───────────────────────────────────────────────────────────────
Write-Step "Copying binary..."
Copy-Item -Path $ExeLocal -Destination $ExeDest -Force
Write-OK "Installed: $ExeDest"

# ─── INSTALL SERVICE ─────────────────────────────────────────────────────────
Write-Step "Running one-shot enrollment..."
& $ExeDest --enroll --server $Server --token $Token
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Enrollment failed (exit code: $LASTEXITCODE)"
    exit 1
}
Write-OK "Enrollment successful"

if (Test-Path $ConfigFile) {
    & icacls $ConfigFile /inheritance:r | Out-Null
    & icacls $ConfigFile /grant:r "SYSTEM:F" "Administrators:F" | Out-Null
    Write-OK "Applied ACL to $ConfigFile"
}

Write-Step "Installing Windows service..."
$BinPath = "`"$ExeDest`" --run"

New-Service `
    -Name        $ServiceName `
    -BinaryPathName $BinPath `
    -DisplayName $DisplayName `
    -StartupType Automatic `
    -Description $Description

# Recovery: restart on failure
sc.exe failure $ServiceName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null

Write-OK "Service '$ServiceName' registered"

# ─── START SERVICE ───────────────────────────────────────────────────────────
Write-Step "Starting service..."
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq 'Running') {
    Write-OK "Service is RUNNING (PID: $(
        (Get-WmiObject Win32_Service -Filter "Name='$ServiceName'").ProcessId
    ))"
} else {
    Write-Fail "Service status: $($svc.Status)"
    Write-Warn "Check logs at: $LogDir\agent.log"
    exit 1
}

# ─── SUMMARY ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  Service   : $ServiceName" -ForegroundColor White
Write-Host "  Status    : $($(Get-Service $ServiceName).Status)" -ForegroundColor White
Write-Host "  Server    : $Server" -ForegroundColor White
Write-Host "  Log file  : $LogDir\agent.log" -ForegroundColor White
Write-Host ""
Write-Host "  Verify with:" -ForegroundColor Yellow
Write-Host "    Get-Service $ServiceName" -ForegroundColor DarkYellow
Write-Host "    Get-Content '$LogDir\agent.log' -Wait" -ForegroundColor DarkYellow
Write-Host "    & '$ExeDest' --diagnose" -ForegroundColor DarkYellow
Write-Host ""
