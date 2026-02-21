param(
    [Parameter(Mandatory = $true)]
    [string]$Dat,

    [Parameter(Mandatory = $true)]
    [string]$Server,

    [Parameter(Mandatory = $true)]
    [string]$BatchId,

    [Parameter(Mandatory = $true)]
    [string]$CallbackKey,

    [string]$LogPath = "C:\ProgramData\Reap3r\deploy-enroll.log",

    [int]$DownloadRetryCount = 2,
    [int]$DownloadRetryBackoffSec = 2,
    [int]$DownloadTimeoutSec = 120
)

# Exit codes:
# 0=OK, 10=ALREADY, 20=DL_FAIL, 30=INST_FAIL, 40=SVC_FAIL, 50=CB_FAIL

$ErrorActionPreference = "Stop"
$PrimaryServiceName = "XEFI-Agent-2"
$LegacyServiceNames = @("MASSVISION-Reap3r-Agent", "Reap3rAgent", "ReaP3rAgent", "xefi-agent-2")
$InstallDir = "C:\Program Files\Reap3r"
$AgentExe = Join-Path $InstallDir "reap3r-agent.exe"
$MaxLogSize = 10MB
$MaxLogFiles = 5
$DownloadRetryCount = [Math]::Max(0, [Math]::Min($DownloadRetryCount, 10))
$DownloadRetryBackoffSec = [Math]::Max(0, [Math]::Min($DownloadRetryBackoffSec, 30))
$DownloadTimeoutSec = [Math]::Max(10, [Math]::Min($DownloadTimeoutSec, 300))

# TLS 1.2 for older Windows.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-ServiceCandidates {
    return @($PrimaryServiceName) + $LegacyServiceNames | Select-Object -Unique
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $dir = Split-Path $LogPath -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    if (Test-Path $LogPath) {
        $size = (Get-Item $LogPath).Length
        if ($size -gt $MaxLogSize) {
            for ($i = $MaxLogFiles; $i -ge 1; $i--) {
                $old = "${LogPath}.${i}"
                $new = "${LogPath}.$($i + 1)"
                if ($i -eq $MaxLogFiles -and (Test-Path $old)) {
                    Remove-Item $old -Force
                } elseif (Test-Path $old) {
                    Rename-Item $old $new -Force
                }
            }
            Rename-Item $LogPath "${LogPath}.1" -Force
        }
    }

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogPath -Value "[$ts] [$Level] $Message" -Encoding UTF8
}

function Convert-ToWsServer {
    param([string]$RawServer)

    $value = if ($null -eq $RawServer) { "" } else { [string]$RawServer }
    $value = $value.Trim().TrimEnd("/")
    if (-not $value) {
        throw "Server URL is empty"
    }

    if ($value -match '^wss?://') {
        if ($value -match '/ws/agent$') {
            return $value
        }
        return "$value/ws/agent"
    }

    if ($value -match '^https?://') {
        $ws = $value -replace '^http://', 'ws://' -replace '^https://', 'wss://'
        if ($ws -notmatch '/ws/agent$') {
            $ws = "$ws/ws/agent"
        }
        return $ws
    }

    throw "Unsupported server URL scheme: $value"
}

function Get-ExistingService {
    foreach ($name in Get-ServiceCandidates) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) {
            return $svc
        }
    }
    return $null
}

function Find-RunningService {
    foreach ($name in Get-ServiceCandidates) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            return $svc
        }
    }
    return $null
}

function Get-PreferredAgentArch {
    try {
        $osArch = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).OSArchitecture
        if ($osArch -match "64") { return "x86_64" }
    } catch {}

    if ($env:PROCESSOR_ARCHITECTURE -match "64") { return "x86_64" }
    return "x86"
}

function Get-DownloadCandidates {
    param(
        [string]$BaseServer,
        [string]$DeployDat,
        [string[]]$Architectures
    )

    $serverBase = $BaseServer.Trim().TrimEnd("/")
    $candidates = @()
    $seen = New-Object System.Collections.Generic.HashSet[string]

    foreach ($arch in $Architectures) {
        $urls = @(
            "$serverBase/api/agent-binary/download?os=windows&arch=$arch&dat=$DeployDat",
            "$serverBase/api/agent-binary/download?os=windows&arch=$arch"
        )
        foreach ($url in $urls) {
            if ($seen.Add($url)) {
                $candidates += [PSCustomObject]@{
                    Url  = $url
                    Arch = $arch
                }
            }
        }
    }

    return $candidates
}

function Invoke-AgentDownload {
    param(
        [array]$Candidates,
        [string]$OutFile,
        [string]$DeployDat,
        [int]$RetryCount,
        [int]$RetryBackoffSec,
        [int]$TimeoutSec
    )

    if (-not $Candidates -or $Candidates.Count -eq 0) {
        throw "No download candidates available"
    }

    $headers = @{ "X-Deploy-DAT" = $DeployDat }
    $attemptsPerUrl = $RetryCount + 1
    $errors = @()

    foreach ($candidate in $Candidates) {
        for ($attempt = 1; $attempt -le $attemptsPerUrl; $attempt++) {
            Write-Log "Download attempt $attempt/$attemptsPerUrl (arch=$($candidate.Arch)) from $($candidate.Url)"
            try {
                Invoke-WebRequest -Uri $candidate.Url -OutFile $OutFile -Headers $headers -UseBasicParsing -TimeoutSec $TimeoutSec
                if (-not (Test-Path $OutFile)) {
                    throw "Output file not created"
                }
                $size = (Get-Item $OutFile).Length
                if ($size -le 0) {
                    throw "Downloaded file is empty"
                }
                return [PSCustomObject]@{
                    Url       = $candidate.Url
                    Arch      = $candidate.Arch
                    SizeBytes = $size
                }
            } catch {
                $errors += "arch=$($candidate.Arch) url=$($candidate.Url) attempt=$attempt error=$($_.Exception.Message)"
                Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
                if ($attempt -lt $attemptsPerUrl -and $RetryBackoffSec -gt 0) {
                    Start-Sleep -Seconds ($RetryBackoffSec * $attempt)
                }
            }
        }
    }

    $summary = ($errors | Select-Object -First 6) -join " | "
    throw "All download attempts failed. $summary"
}

function Test-AgentSupportsFlag {
    param(
        [string]$ExePath,
        [string]$Flag
    )

    if (-not (Test-Path $ExePath)) { return $false }

    try {
        $helpText = (& $ExePath --help 2>&1 | Out-String)
        return $helpText -match [Regex]::Escape($Flag)
    } catch {
        return $false
    }
}

function Invoke-AgentProcess {
    param([string[]]$Arguments)

    $proc = Start-Process -FilePath $AgentExe -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
    return $proc.ExitCode
}

function Send-Callback {
    param(
        [int]$ExitCode,
        [string]$Status,
        [string]$Message = "",
        [string]$AgentId = "",
        [string]$Version = ""
    )

    $body = @{
        batch_id     = $BatchId
        zabbix_host  = $env:COMPUTERNAME
        computername = $env:COMPUTERNAME
        hostname     = $env:COMPUTERNAME
        exit_code    = $ExitCode
        status       = $Status
        message      = $Message
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
    }
}

$exitCode = 0
$tempExe = $null

try {
    if ($Dat.Length -ne 64 -or $Dat -notmatch '^[a-fA-F0-9]{64}$') {
        throw "DAT must be a 64-char hex string"
    }

    $wsServer = Convert-ToWsServer -RawServer $Server

    Write-Log "=== Reap3r enrollment start ==="
    Write-Log "Host: $env:COMPUTERNAME | Batch: $BatchId | DAT: $($Dat.Substring(0, 8))***"
    Write-Log "Server HTTP: $Server"
    Write-Log "Server WS  : $wsServer"

    $alreadySvc = Find-RunningService
    if ($alreadySvc -and (Test-Path $AgentExe)) {
        Write-Log "Agent already installed and running ($($alreadySvc.Name)); skipping"
        $exitCode = 10
        Send-Callback -ExitCode 10 -Status "ALREADY_INSTALLED" -Message "Service $($alreadySvc.Name) is already running"
        exit 10
    }

    $preferredArch = Get-PreferredAgentArch
    $archCandidates = if ($preferredArch -eq "x86_64") { @("x86_64", "x86") } else { @("x86") }

    Write-Log "Downloading agent binary... preferred_arch=$preferredArch candidates=$($archCandidates -join ',')"
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    $downloadCandidates = Get-DownloadCandidates -BaseServer $Server -DeployDat $Dat -Architectures $archCandidates
    $tempExe = Join-Path $env:TEMP ("reap3r-agent-download-{0}.exe" -f ([Guid]::NewGuid().ToString("N")))

    try {
        $dl = Invoke-AgentDownload `
            -Candidates $downloadCandidates `
            -OutFile $tempExe `
            -DeployDat $Dat `
            -RetryCount $DownloadRetryCount `
            -RetryBackoffSec $DownloadRetryBackoffSec `
            -TimeoutSec $DownloadTimeoutSec
        Write-Log "Download complete: arch=$($dl.Arch) size=$(([double]$dl.SizeBytes / 1MB).ToString('F2')) MB source=$($dl.Url)"
    } catch {
        Write-Log "Download FAILED: $_" "ERROR"
        $exitCode = 20
        Send-Callback -ExitCode 20 -Status "DOWNLOAD_FAILED" -Message "$_"
        exit 20
    }

    foreach ($name in Get-ServiceCandidates) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Stopped") {
            Write-Log "Stopping existing service: $name"
            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Log "Installing agent to $InstallDir..."
    try {
        Copy-Item -Path $tempExe -Destination $AgentExe -Force
        Remove-Item $tempExe -Force -ErrorAction SilentlyContinue
        $tempExe = $null

        $supportsInstall = Test-AgentSupportsFlag -ExePath $AgentExe -Flag "--install"
        $supportsEnroll = Test-AgentSupportsFlag -ExePath $AgentExe -Flag "--enroll"
        $supportsRun = Test-AgentSupportsFlag -ExePath $AgentExe -Flag "--run"

        if ($supportsInstall) {
            Write-Log "Using native installer (--install)..."
            $installCode = Invoke-AgentProcess -Arguments @("--install", "--server", $wsServer, "--token", $Dat)
            if ($installCode -ne 0) {
                throw "Agent --install failed with exit code $installCode"
            }
        } else {
            if (-not $supportsEnroll) {
                throw "Agent binary too old: missing --install and --enroll support"
            }

            Write-Log "Fallback mode: --enroll + service registration"
            $enrollCode = Invoke-AgentProcess -Arguments @("--enroll", "--server", $wsServer, "--token", $Dat)
            if ($enrollCode -ne 0) {
                throw "Agent --enroll failed with exit code $enrollCode"
            }

            $existingSvc = Get-ExistingService
            $serviceName = if ($existingSvc) { $existingSvc.Name } else { $PrimaryServiceName }
            $binPath = if ($supportsRun) { "`"$AgentExe`" --run" } else { "`"$AgentExe`"" }

            if ($existingSvc) {
                & sc.exe config $serviceName binPath= $binPath start= auto | Out-Null
            } else {
                New-Service -Name $serviceName `
                    -BinaryPathName $binPath `
                    -DisplayName "Reap3r Agent" `
                    -Description "MASSVISION Reap3r endpoint agent" `
                    -StartupType Automatic | Out-Null
            }

            & sc.exe description $serviceName "MASSVISION Reap3r endpoint agent" | Out-Null
            & sc.exe failure $serviceName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
            & sc.exe failureflag $serviceName 1 | Out-Null
            Start-Service -Name $serviceName
        }
    } catch {
        Write-Log "Install FAILED: $_" "ERROR"
        $exitCode = 30
        Send-Callback -ExitCode 30 -Status "INSTALL_FAILED" -Message "$_"
        exit 30
    }

    Write-Log "Waiting for service to reach Running state..."
    $running = $null
    for ($i = 0; $i -lt 30; $i++) {
        $running = Find-RunningService
        if ($running) { break }
        Start-Sleep -Seconds 1
    }

    if (-not $running) {
        $exitCode = 40
        Write-Log "Service start FAILED: no running service found in candidates" "ERROR"
        Send-Callback -ExitCode 40 -Status "SERVICE_START_FAILED" -Message "No running service found after install"
        exit 40
    }

    $version = ""
    try {
        $version = (& $AgentExe --version 2>$null | Select-Object -First 1).Trim()
    } catch {}

    Write-Log "Enrollment SUCCESS - service $($running.Name) running"
    Send-Callback -ExitCode 0 -Status "INSTALLED" -Message "Agent installed and running on $env:COMPUTERNAME ($($running.Name))" -Version $version
}
catch {
    Write-Log "UNEXPECTED ERROR: $_" "ERROR"
    if ($exitCode -eq 0) { $exitCode = 30 }
    Send-Callback -ExitCode $exitCode -Status "UNEXPECTED_ERROR" -Message "$_"
}
finally {
    if ($tempExe -and (Test-Path $tempExe)) {
        Remove-Item $tempExe -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode
