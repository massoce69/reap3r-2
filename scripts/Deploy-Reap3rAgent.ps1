# ─────────────────────────────────────────────────────────────
# MASSVISION Reap3r — Agent Enrollment Script (Zabbix Deploy)
# Idempotent: checks if agent is already installed + running
# Called via Zabbix global script (script.execute)
# Exit codes: 0=OK, 10=ALREADY, 20=DL_FAIL, 30=INST_FAIL, 40=SVC_FAIL, 50=CB_FAIL
# ─────────────────────────────────────────────────────────────

param(
    [Parameter(Mandatory=$true)]
    [string]$Dat,

    [Parameter(Mandatory=$true)]
    [string]$Server,

    [Parameter(Mandatory=$true)]
    [string]$BatchId,

    [Parameter(Mandatory=$true)]
    [string]$CallbackKey,

    [string]$LogPath = "C:\ProgramData\Reap3r\deploy-enroll.log"
)

# ═══════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════
$ErrorActionPreference = "Stop"
$ServiceName = "Reap3rAgent"
$InstallDir = "C:\Program Files\Reap3r"
$AgentExe = Join-Path $InstallDir "reap3r-agent.exe"
$MaxLogSize = 10MB
$MaxLogFiles = 5

# TLS 1.2 for older Windows
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ═══════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $dir = Split-Path $LogPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    # Rotate if needed
    if (Test-Path $LogPath) {
        $size = (Get-Item $LogPath).Length
        if ($size -gt $MaxLogSize) {
            for ($i = $MaxLogFiles; $i -ge 1; $i--) {
                $old = "${LogPath}.${i}"
                $new = "${LogPath}.$($i+1)"
                if ($i -eq $MaxLogFiles -and (Test-Path $old)) { Remove-Item $old -Force }
                elseif (Test-Path $old) { Rename-Item $old $new -Force }
            }
            Rename-Item $LogPath "${LogPath}.1" -Force
        }
    }

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

# ═══════════════════════════════════════════
# CALLBACK
# ═══════════════════════════════════════════
function Send-Callback {
    param(
        [int]$ExitCode,
        [string]$Status,
        [string]$Message = "",
        [string]$AgentId = "",
        [string]$Version = ""
    )

    $body = @{
        batch_id    = $BatchId
        zabbix_host = $env:COMPUTERNAME
        exit_code   = $ExitCode
        status      = $Status
        message     = $Message
        hostname    = $env:COMPUTERNAME
    }
    if ($AgentId) { $body["agent_id"] = $AgentId }
    if ($Version) { $body["version"] = $Version }

    $json = $body | ConvertTo-Json -Compress
    $callbackUrl = "$Server/api/deploy/zabbix/callback"

    try {
        $headers = @{
            "Content-Type" = "application/json"
            "X-Deploy-Callback-Key" = $CallbackKey
        }
        Invoke-RestMethod -Uri $callbackUrl -Method POST -Body $json -Headers $headers -TimeoutSec 30 | Out-Null
        Write-Log "Callback sent: $Status (exit=$ExitCode)"
    } catch {
        Write-Log "Callback FAILED: $_" "ERROR"
        # Don't change exit code for callback failure — report original status
    }
}

# ═══════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════
$exitCode = 0

try {
    Write-Log "═══ Reap3r Enrollment Start ═══"
    Write-Log "Host: $env:COMPUTERNAME | DAT: $($Dat.Substring(0, [Math]::Min(8, $Dat.Length)))*** | Batch: $BatchId"
    Write-Log "Server: $Server"

    # ── 1. Idempotence check ──
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Log "Agent already installed and running — skipping"
        $exitCode = 10
        Send-Callback -ExitCode 10 -Status "ALREADY_INSTALLED" -Message "Service $ServiceName is already running"
        exit 10
    }

    # ── 2. Download agent ──
    Write-Log "Downloading agent binary..."
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

    $downloadUrl = "$Server/api/agent-binary/download?os=windows&arch=x86_64&dat=$Dat"
    $tempExe = Join-Path $env:TEMP "reap3r-agent-download.exe"

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("X-Deploy-DAT", $Dat)
        $wc.DownloadFile($downloadUrl, $tempExe)
        Write-Log "Download complete: $(((Get-Item $tempExe).Length / 1MB).ToString('F2')) MB"
    } catch {
        Write-Log "Download FAILED: $_" "ERROR"
        $exitCode = 20
        Send-Callback -ExitCode 20 -Status "DOWNLOAD_FAILED" -Message "$_"
        exit 20
    }

    # ── 3. Stop existing service if present ──
    if ($svc) {
        Write-Log "Stopping existing service..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    # ── 4. Install / copy binary ──
    Write-Log "Installing agent to $InstallDir..."
    try {
        Copy-Item -Path $tempExe -Destination $AgentExe -Force
        Remove-Item $tempExe -Force -ErrorAction SilentlyContinue

        # Write config if not exists
        $configPath = Join-Path $InstallDir "config.json"
        if (-not (Test-Path $configPath)) {
            $config = @{
                server_url = $Server
                dat        = $Dat
                log_level  = "info"
            } | ConvertTo-Json
            Set-Content -Path $configPath -Value $config -Encoding UTF8
            Write-Log "Config written to $configPath"
        }
    } catch {
        Write-Log "Install FAILED: $_" "ERROR"
        $exitCode = 30
        Send-Callback -ExitCode 30 -Status "INSTALL_FAILED" -Message "$_"
        exit 30
    }

    # ── 5. Create/start Windows service ──
    Write-Log "Configuring Windows service..."
    try {
        $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $existingSvc) {
            # Create service
            $binPath = "`"$AgentExe`" service"
            New-Service -Name $ServiceName -BinaryPathName $binPath `
                -DisplayName "Reap3r Agent" `
                -Description "MASSVISION Reap3r endpoint agent" `
                -StartupType Automatic | Out-Null
            Write-Log "Service created"
        }

        Start-Service -Name $ServiceName
        Start-Sleep -Seconds 3

        $svcCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svcCheck.Status -ne "Running") {
            throw "Service did not start (status: $($svcCheck.Status))"
        }
        Write-Log "Service started successfully"
    } catch {
        Write-Log "Service start FAILED: $_" "ERROR"
        $exitCode = 40
        Send-Callback -ExitCode 40 -Status "SERVICE_START_FAILED" -Message "$_"
        exit 40
    }

    # ── 6. Success ──
    Write-Log "═══ Enrollment SUCCESS ═══"
    $exitCode = 0
    Send-Callback -ExitCode 0 -Status "INSTALLED" -Message "Agent installed and running on $env:COMPUTERNAME"

} catch {
    Write-Log "UNEXPECTED ERROR: $_" "ERROR"
    if ($exitCode -eq 0) { $exitCode = 30 }
    Send-Callback -ExitCode $exitCode -Status "UNEXPECTED_ERROR" -Message "$_"
} finally {
    # Cleanup temp files
    $tempExe = Join-Path $env:TEMP "reap3r-agent-download.exe"
    if (Test-Path $tempExe) { Remove-Item $tempExe -Force -ErrorAction SilentlyContinue }
}

exit $exitCode
