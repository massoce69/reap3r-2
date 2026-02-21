#Requires -RunAsAdministrator
<#
.SYNOPSIS
    MASSVISION Reap3r Agent - Windows installer (fallback / CI use)

.DESCRIPTION
    Installs reap3r-agent.exe as a Windows service.
    Prefers native agent install flow (--install), with fallback for older binaries.
#>
param(
    [string]$Server = "",
    [string]$Token = "",
    [string]$ExeSource = "",
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ServiceName = "XEFI-Agent-2"
$LegacyServiceNames = @("MASSVISION-Reap3r-Agent", "Reap3rAgent", "ReaP3rAgent", "xefi-agent-2")
$ServiceCandidates = (@($ServiceName) + $LegacyServiceNames | Select-Object -Unique)
$DisplayName = "Reap3r Agent (MASSVISION)"
$Description = "MASSVISION Reap3r remote-management agent"
$InstallDir = "C:\Program Files\Reap3r Agent"
$DataDir = "C:\ProgramData\XefiAgent2"
$LegacyDataDir = "C:\ProgramData\Reap3r"
$ExeDest = "$InstallDir\reap3r-agent.exe"
$LogCandidates = @(
    "$DataDir\logs\agent.log",
    "$LegacyDataDir\logs\agent.log"
)

function Write-Step([string]$msg) { Write-Host "`n[+] $msg" -ForegroundColor Cyan }
function Write-OK([string]$msg) { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "    [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) { Write-Host "    [FAIL] $msg" -ForegroundColor Red }

function Resolve-AgentLogPath {
    foreach ($path in $LogCandidates) {
        if (Test-Path $path) { return $path }
    }
    return $LogCandidates[0]
}

function Resolve-AgentConfigPath {
    $candidates = @("$DataDir\agent.conf", "$LegacyDataDir\agent.conf")
    foreach ($path in $candidates) {
        if (Test-Path $path) { return $path }
    }
    return $candidates[0]
}

function Resolve-ActiveServiceName {
    foreach ($svcName in $ServiceCandidates) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) { return $svcName }
    }
    return $ServiceName
}

if ($Uninstall) {
    Write-Step "Uninstalling Reap3r Agent..."
    foreach ($svcName in $ServiceCandidates) {
        try { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue } catch {}
        try { sc.exe delete $svcName | Out-Null } catch {}
    }

    if (Test-Path $ExeDest) { Remove-Item $ExeDest -Force }
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }

    Write-OK "Service removed."
    Write-Warn "Config/logs in $DataDir (and legacy $LegacyDataDir) were kept."
    exit 0
}

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Magenta
Write-Host "  MASSVISION Reap3r Agent - Windows Installer" -ForegroundColor Magenta
Write-Host "=======================================================" -ForegroundColor Magenta

if (-not $Server) { $Server = Read-Host "  Enter Server URL (e.g. wss://YOUR_SERVER/ws/agent)" }
if (-not $Token) { $Token = Read-Host "  Enter Enrollment Token" }

if (-not ($Server -match '^wss?://')) {
    Write-Fail "Server URL must start with ws:// or wss://. Got: $Server"
    exit 1
}
if (-not $Token) {
    Write-Fail "Enrollment token is required."
    exit 1
}

Write-Step "Locating agent executable..."
$ExeLocal = ""
if ($ExeSource -match '^https?://') {
    $tmpExe = "$env:TEMP\reap3r-agent.exe"
    try {
        Invoke-WebRequest -Uri $ExeSource -OutFile $tmpExe -UseBasicParsing
        $ExeLocal = $tmpExe
        Write-OK "Downloaded to $tmpExe"
    } catch {
        Write-Fail "Download failed: $_"
        exit 1
    }
} elseif ($ExeSource -and (Test-Path $ExeSource)) {
    $ExeLocal = (Resolve-Path $ExeSource).Path
    Write-OK "Using provided path: $ExeLocal"
} else {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidates = @(
        "$scriptDir\xefi-agent-2.exe",
        "$scriptDir\reap3r-agent.exe",
        "$scriptDir\..\target\release\reap3r-agent.exe",
        "$scriptDir\..\target\release\xefi-agent-2.exe",
        "$scriptDir\..\target\x86_64-pc-windows-msvc\release\reap3r-agent.exe",
        "$scriptDir\..\target\x86_64-pc-windows-msvc\release\xefi-agent-2.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            $ExeLocal = (Resolve-Path $c).Path
            break
        }
    }
    if (-not $ExeLocal) {
        Write-Fail "Cannot find agent executable. Pass -ExeSource <path> or <url>."
        exit 1
    }
    Write-OK "Found: $ExeLocal"
}

Write-Step "Stopping existing service (if any)..."
$removedAny = $false
foreach ($svcName in $ServiceCandidates) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    if ($svc.Status -ne "Stopped") {
        Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    sc.exe delete $svcName | Out-Null
    Start-Sleep -Milliseconds 500
    Write-OK "Old service removed: $svcName"
    $removedAny = $true
}
if (-not $removedAny) { Write-OK "No existing service" }

Write-Step "Creating directories..."
foreach ($d in @($InstallDir, $DataDir, "$DataDir\logs")) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    Write-OK $d
}
if (-not (Test-Path $LegacyDataDir)) {
    New-Item -ItemType Directory -Path $LegacyDataDir -Force | Out-Null
}

Write-Step "Copying binary..."
Copy-Item -Path $ExeLocal -Destination $ExeDest -Force
Write-OK "Installed: $ExeDest"

Write-Step "Installing service + enrollment..."
$supportsInstall = $false
$supportsEnroll = $false
$supportsRun = $false
try {
    $helpText = (& $ExeDest --help 2>&1 | Out-String)
    if ($helpText -match '--install') { $supportsInstall = $true }
    if ($helpText -match '--enroll') { $supportsEnroll = $true }
    if ($helpText -match '--run') { $supportsRun = $true }
} catch {}

$activeServiceName = $ServiceName
if ($supportsInstall) {
    $proc = Start-Process -FilePath $ExeDest -ArgumentList @("--install", "--server", $Server, "--token", $Token) -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        Write-Fail "Agent --install failed (exit code: $($proc.ExitCode))"
        exit 1
    }
    $activeServiceName = Resolve-ActiveServiceName
    Write-OK "Native install completed (service: $activeServiceName)"
} else {
    if (-not $supportsEnroll) {
        Write-Fail "This binary does not support --install or --enroll."
        exit 1
    }

    & $ExeDest --enroll --server $Server --token $Token
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Enrollment failed (exit code: $LASTEXITCODE)"
        exit 1
    }
    Write-OK "Enrollment successful"

    $binPath = if ($supportsRun) { "`"$ExeDest`" --run" } else { "`"$ExeDest`"" }
    New-Service `
        -Name $ServiceName `
        -BinaryPathName $binPath `
        -DisplayName $DisplayName `
        -StartupType Automatic `
        -Description $Description
    $activeServiceName = $ServiceName
    Write-OK "Service '$activeServiceName' registered (fallback mode)"
}

$resolvedConfig = Resolve-AgentConfigPath
if (Test-Path $resolvedConfig) {
    & icacls $resolvedConfig /inheritance:r | Out-Null
    & icacls $resolvedConfig /grant:r "SYSTEM:F" "Administrators:F" | Out-Null
    Write-OK "Applied ACL to $resolvedConfig"
}

sc.exe failure $activeServiceName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
sc.exe failureflag $activeServiceName 1 | Out-Null

Write-Step "Starting service..."
Start-Service -Name $activeServiceName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

$svc = Get-Service -Name $activeServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    $pid = (Get-WmiObject Win32_Service -Filter "Name='$activeServiceName'").ProcessId
    Write-OK "Service is RUNNING (PID: $pid)"
} else {
    $status = if ($svc) { $svc.Status } else { "NOT FOUND" }
    Write-Fail "Service status: $status"
    Write-Warn "Check logs at: $(Resolve-AgentLogPath)"
    exit 1
}

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Service   : $activeServiceName" -ForegroundColor White
Write-Host "  Status    : $($(Get-Service $activeServiceName).Status)" -ForegroundColor White
Write-Host "  Server    : $Server" -ForegroundColor White
Write-Host "  Log file  : $(Resolve-AgentLogPath)" -ForegroundColor White
Write-Host ""
Write-Host "  Verify with:" -ForegroundColor Yellow
Write-Host "    Get-Service $activeServiceName" -ForegroundColor DarkYellow
Write-Host "    Get-Content '$(Resolve-AgentLogPath)' -Wait" -ForegroundColor DarkYellow
Write-Host "    & '$ExeDest' --diagnose" -ForegroundColor DarkYellow
Write-Host ""
