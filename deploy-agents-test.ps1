#!/usr/bin/env pwsh
#Requires -Version 5.1
<#
.SYNOPSIS
  Deploy XEFI Agent 2 to a list of Windows servers (test run).
.DESCRIPTION
  1. Builds the Rust agent locally (cargo build --release)
  2. Copies the binary and installs/restarts the service on each remote server
     via PSRemoting (WinRM). Runs all 10 servers in parallel with runspaces.
.PARAMETER ServerUrl
  XEFI backend URL, e.g. https://massvision.pro
.PARAMETER Token
  Enrollment token (hex-64). If omitted you will be prompted.
.PARAMETER Credential
  PSCredential to use. If omitted, current Windows identity is used (domain auth).
.PARAMETER NoBuild
  Skip cargo build (use existing binary in target/release/).
.EXAMPLE
  .\deploy-agents-test.ps1 -ServerUrl https://massvision.pro -Token <hex>
#>
param(
  [string]$ServerUrl  = 'https://massvision.pro',
  [string]$Token      = '',
  [System.Management.Automation.PSCredential]$Credential = $null,
  [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'

# ── Target servers ────────────────────────────────────────────────────────────
$SERVERS = @(
  'BYBRDS4-1640009772',
  'FICHIERS-1766067796',
  'vFILES-2022-1731077544',
  'SRV-DATA2K19-1743009465',
  'SRVAD-1702558572',
  'HYPERV-DRLEFORT-1765472279',
  'FTEAGRAPP01-1764263026',
  'SRV-APPLI-1651683876',
  'SRV-FILE-1765990663',
  'CHAVANON-APP-1761121585'
)

# ── Colours ───────────────────────────────────────────────────────────────────
function Write-Header([string]$msg) { Write-Host "`n$msg" -ForegroundColor Cyan }
function Write-OK([string]$msg)     { Write-Host "  [OK]  $msg" -ForegroundColor Green }
function Write-FAIL([string]$msg)   { Write-Host "  [ERR] $msg" -ForegroundColor Red }
function Write-Warn([string]$msg)   { Write-Host "  [!]   $msg" -ForegroundColor Yellow }

# ── 0. Prompt for token if missing ───────────────────────────────────────────
if ([string]::IsNullOrWhiteSpace($Token)) {
  $Token = (Read-Host "Enrollment token (hex-64)").Trim()
}
if ($Token.Length -ne 64 -or $Token -notmatch '^[a-fA-F0-9]+$') {
  Write-FAIL "Token must be a 64-char hex string. Aborting."
  exit 1
}

$ServerUrl = $ServerUrl.TrimEnd('/')
$wsUrl = ($ServerUrl -replace '^https?://', { if ($_.Value -match 'https') { 'wss://' } else { 'ws://' } }) + '/ws/agent'
# Simpler compat approach:
$wsUrl = ($ServerUrl -replace '^http://', 'ws://') -replace '^https://', 'wss://'
$wsUrl = "$wsUrl/ws/agent"

# ── 1. Build agent binary ─────────────────────────────────────────────────────
$REPO = $PSScriptRoot
$AGENT_SRC = Join-Path $REPO 'agent'
$BIN_LOCAL = Join-Path $AGENT_SRC 'target\release\xefi-agent-2.exe'

if (-not $NoBuild) {
  Write-Header "Step 1/3 — Building XEFI Agent 2 (release)..."
  Push-Location $AGENT_SRC
  try {
    & cargo build --release 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }
  } finally { Pop-Location }
  Write-OK "Build complete: $BIN_LOCAL"
} else {
  Write-Warn "Skipping build (NoBuild flag set)"
}

if (-not (Test-Path $BIN_LOCAL)) {
  Write-FAIL "Binary not found: $BIN_LOCAL"
  Write-FAIL "Run without -NoBuild or copy the binary manually."
  exit 1
}
$binSize = (Get-Item $BIN_LOCAL).Length
Write-OK "Binary ready: $([math]::Round($binSize/1MB,2)) MB"

# ── 2. Deploy to all servers in parallel ─────────────────────────────────────
Write-Header "Step 2/3 — Deploying to $($SERVERS.Count) servers (parallel)..."

# Runspace pool for parallelism
$pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $SERVERS.Count)
$pool.Open()

$scriptBlock = {
  param($server, $binPath, $wsUrl, $token, $cred)

  $result = [PSCustomObject]@{
    Server  = $server
    Status  = 'Unknown'
    Message = ''
  }

  $INSTALL_DIR  = 'C:\Program Files\XEFI\Agent2'
  $EXE_NAME     = 'xefi-agent-2.exe'
  $REMOTE_EXE   = Join-Path $INSTALL_DIR $EXE_NAME
  $SERVICE_NAME = 'XEFI-Agent-2'

  $psParams = @{
    ComputerName  = $server
    ErrorAction   = 'Stop'
  }
  if ($cred) { $psParams.Credential = $cred }

  try {
    # Test WinRM reachability first
    $null = Test-WSMan -ComputerName $server -ErrorAction Stop

    # Copy binary to remote host via admin share
    $adminShare = "\\$server\C$\Windows\Temp\$EXE_NAME"
    if ($cred) {
      $copyParams = @{ Credential = $cred }
    } else {
      $copyParams = @{}
    }
    Copy-Item -Path $binPath -Destination $adminShare -Force @copyParams

    # Remote installation via Invoke-Command
    $output = Invoke-Command @psParams -ScriptBlock {
      param($installDir, $remoteTmp, $exeName, $serviceName, $wsUrl, $token)
      $exePath = Join-Path $installDir $exeName
      $tmpExe  = $remoteTmp

      try {
        # Ensure install dir
        New-Item -ItemType Directory -Force -Path $installDir | Out-Null

        # ── Stop ONLY our own agent service — never touch other XEFI services ──
        # Verify the service is ours by checking the binary path before stopping it.
        $ours = @('XEFI-Agent-2', 'MASSVISION-Reap3r-Agent', 'ReaP3rAgent')
        foreach ($svcName in $ours) {
          $svc = Get-Service $svcName -ErrorAction SilentlyContinue
          if (-not $svc) { continue }
          # Extra safety: confirm the image path belongs to XEFI Agent / Reap3r
          $imgPath = (Get-WmiObject Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue).PathName
          if ($imgPath -and ($imgPath -notmatch 'xefi-agent-2|reap3r-agent' -and $imgPath -notmatch 'MASSVISION')) {
            # This name is taken by a different (non-agent) service — skip it completely
            continue
          }
          try { Stop-Service $svcName -Force -ErrorAction SilentlyContinue } catch {}
        }
        # Kill orphan agent processes only (by exact exe name)
        Stop-Process -Name 'xefi-agent-2' -Force -ErrorAction SilentlyContinue
        Stop-Process -Name 'reap3r-agent'  -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1

        # Move binary from temp
        Move-Item -Path $tmpExe -Destination $exePath -Force

        # Install/register service
        $proc = Start-Process -FilePath $exePath `
          -ArgumentList '--install', '--server', $wsUrl, '--token', $token `
          -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
          throw "xefi-agent-2 --install exited with code $($proc.ExitCode)"
        }

        # Verify
        Start-Sleep -Seconds 2
        $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
        if (-not $svc) { throw "Service '$serviceName' not found after install" }
        if ($svc.Status -ne 'Running') { throw "Service status: $($svc.Status) (expected Running)" }

        return "OK — service $serviceName is Running"
      } catch {
        return "ERROR: $_"
      }
    } -ArgumentList $installDir, "C:\Windows\Temp\$exeName", $exeName, $serviceName, $wsUrl, $token

    if ($output -match '^OK') {
      $result.Status  = 'Success'
      $result.Message = $output
    } else {
      $result.Status  = 'Failed'
      $result.Message = $output
    }

  } catch {
    $result.Status  = 'Failed'
    $result.Message = "[$($_.Exception.GetType().Name)] $($_.Message)"
  }

  return $result
}

# Launch all runspaces
$handles = foreach ($srv in $SERVERS) {
  $ps = [System.Management.Automation.PowerShell]::Create()
  $ps.RunspacePool = $pool
  $null = $ps.AddScript($scriptBlock).AddParameters(@{
    server  = $srv
    binPath = $BIN_LOCAL
    wsUrl   = $wsUrl
    token   = $Token
    cred    = $Credential
  })
  [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Server = $srv }
}

# Collect results with spinner
Write-Host ""
$done = 0
$results = @()
while ($done -lt $handles.Count) {
  foreach ($h in $handles | Where-Object { $_.Handle.IsCompleted -and -not $_.PS.HadErrors -and $null -eq $_.Result }) {
    $res = $h.PS.EndInvoke($h.Handle)
    $h | Add-Member -NotePropertyName Result -NotePropertyValue $res -Force
    $done++
    $r = $res[0]
    if ($r.Status -eq 'Success') {
      Write-OK "$($r.Server): $($r.Message)"
    } else {
      Write-FAIL "$($r.Server): $($r.Message)"
    }
    $results += $r
  }
  # catch runspace errors
  foreach ($h in $handles | Where-Object { $_.Handle.IsCompleted -and $_.PS.HadErrors -and $null -eq $_.Result }) {
    $h | Add-Member -NotePropertyName Result -NotePropertyValue $null -Force
    $done++
    Write-FAIL "$($h.Server): Runspace error — $($h.PS.Streams.Error -join ' | ')"
    $results += [PSCustomObject]@{ Server = $h.Server; Status = 'Failed'; Message = $h.PS.Streams.Error[0] }
  }
  if ($done -lt $handles.Count) { Start-Sleep -Milliseconds 500 }
}

$handles | ForEach-Object { $_.PS.Dispose() }
$pool.Close(); $pool.Dispose()

# ── 3. Summary ────────────────────────────────────────────────────────────────
Write-Header "Step 3/3 — Summary"
$ok   = ($results | Where-Object Status -eq 'Success').Count
$fail = ($results | Where-Object Status -ne 'Success').Count

$results | Format-Table -AutoSize -Property Server, Status, Message

Write-Host ""
Write-Host "  Success : $ok / $($SERVERS.Count)" -ForegroundColor $(if ($ok -eq $SERVERS.Count) { 'Green' } else { 'Yellow' })
if ($fail -gt 0) {
  Write-Host "  Failed  : $fail / $($SERVERS.Count)" -ForegroundColor Red
  Write-Host ""
  Write-Warn "For failed servers, verify:"
  Write-Warn "  1. WinRM is enabled:  Invoke-Command -ComputerName <srv> { hostname }"
  Write-Warn "  2. Admin share works: Test-Path \\<srv>\C`$"
  Write-Warn "  3. Firewall allows WinRM (TCP 5985/5986)"
  Write-Warn "  4. You have local admin rights on the target"
}
Write-Host ""
