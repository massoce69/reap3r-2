# ─────────────────────────────────────────────────────────────
# MassVision Agent – Windows Installation Script
# Run as Administrator
# ─────────────────────────────────────────────────────────────
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,

    [Parameter(Mandatory=$true)]
    [string]$EnrollmentToken,

    [string]$InstallDir = "C:\Program Files\MassVision"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host "=== MassVision Agent Installer ===" -ForegroundColor Cyan

# 1) Create directories
Write-Host "[1/6] Creating directories..."
$dirs = @(
    $InstallDir,
    "C:\ProgramData\MassVision",
    "C:\ProgramData\MassVision\logs",
    "C:\ProgramData\MassVision\staging",
    "C:\ProgramData\MassVision\rollback",
    "C:\ProgramData\MassVision\modules",
    "C:\ProgramData\MassVision\sandbox"
)
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

# 2) Copy binary
Write-Host "[2/6] Installing binary..."
$sourceBinary = Join-Path $PSScriptRoot "..\massvision-agent.exe"
if (-not (Test-Path $sourceBinary)) {
    # Try release build
    $sourceBinary = Join-Path $PSScriptRoot "..\target\release\massvision-agent.exe"
}
if (-not (Test-Path $sourceBinary)) {
    Write-Error "Cannot find massvision-agent.exe. Build the project first: cargo build --release"
    exit 1
}
Copy-Item $sourceBinary "$InstallDir\massvision-agent.exe" -Force

# 3) Copy config
Write-Host "[3/6] Installing configuration..."
$sourceConfig = Join-Path $PSScriptRoot "..\config.toml"
if (Test-Path $sourceConfig) {
    $config = Get-Content $sourceConfig -Raw
    $config = $config -replace 'url\s*=\s*"https://massvision\.example\.com"', "url         = `"$ServerUrl`""
    $config = $config -replace 'ws_url\s*=\s*"wss://massvision\.example\.com/ws/agents"', "ws_url      = `"$($ServerUrl -replace 'https','wss')/ws/agents`""
    Set-Content "C:\ProgramData\MassVision\config.toml" $config
} else {
    Write-Warning "config.toml not found, using defaults"
}

# 4) Enroll agent
Write-Host "[4/6] Enrolling agent with server..."
$enrollResult = & "$InstallDir\massvision-agent.exe" enroll --token $EnrollmentToken --server $ServerUrl 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Enrollment failed: $enrollResult"
    exit 1
}
Write-Host $enrollResult

# 5) Install Windows Service
Write-Host "[5/6] Installing Windows service..."
& "$InstallDir\massvision-agent.exe" install 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Service installation via agent failed, trying sc.exe..."
    sc.exe create MassVisionAgent binPath= "`"$InstallDir\massvision-agent.exe`"" start= auto DisplayName= "MassVision Agent"
    sc.exe failure MassVisionAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000
}

# 6) Start service
Write-Host "[6/6] Starting service..."
Start-Service MassVisionAgent -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$svc = Get-Service MassVisionAgent -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host ""
    Write-Host "=== Installation Complete ===" -ForegroundColor Green
    Write-Host "Service Status : Running"
    Write-Host "Install Dir    : $InstallDir"
    Write-Host "Data Dir       : C:\ProgramData\MassVision"
    Write-Host "Logs           : C:\ProgramData\MassVision\logs"
} else {
    Write-Warning "Service may not be running. Check: Get-Service MassVisionAgent"
}
