<#
.SYNOPSIS
    MASSVISION Reap3r Agent - Windows smoke test

.DESCRIPTION
    Checks service status, agent logs, enrollment/heartbeat markers,
    and optionally submits a lightweight test job through the backend API.
#>
param(
    [string]$BackendUrl    = "http://localhost:4000",
    [string]$AdminEmail    = "",
    [string]$AdminPassword = "",
    [int]$WaitSeconds      = 30,
    [switch]$SkipJobTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$ServiceCandidates = @("XEFI-Agent-2", "MASSVISION-Reap3r-Agent", "Reap3rAgent", "ReaP3rAgent", "xefi-agent-2")
$LogCandidates = @(
    "C:\ProgramData\XefiAgent2\logs\agent.log",
    "C:\ProgramData\Reap3r\logs\agent.log"
)
$Passed = 0
$Failed = 0

function Write-Check([string]$name, [bool]$ok, [string]$detail = "") {
    if ($ok) {
        Write-Host "  [PASS] $name" -ForegroundColor Green
        if ($detail) { Write-Host "         $detail" -ForegroundColor DarkGreen }
        $script:Passed++
    } else {
        Write-Host "  [FAIL] $name" -ForegroundColor Red
        if ($detail) { Write-Host "         $detail" -ForegroundColor DarkRed }
        $script:Failed++
    }
}

function Get-AgentService {
    foreach ($name in $ServiceCandidates) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) { return $svc }
    }
    return $null
}

function Get-AgentLogPath {
    foreach ($path in $LogCandidates) {
        if (Test-Path $path) { return $path }
    }
    return $LogCandidates[0]
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Reap3r Agent - Windows Smoke Test"                    -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"            -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$svc = Get-AgentService
$serviceName = if ($svc) { $svc.Name } else { $ServiceCandidates[0] }
$logFile = Get-AgentLogPath

# CHECK 1: Service exists
Write-Host "[ CHECK 1 ] Service installed" -ForegroundColor White
Write-Check "Service exists (candidate set)" `
    ($null -ne $svc) `
    $(if ($svc) { "Detected: $($svc.Name), status=$($svc.Status)" } else { "Not found. Run install-windows.ps1 first." })

# CHECK 2: Service running
Write-Host ""
Write-Host "[ CHECK 2 ] Service running" -ForegroundColor White
Write-Check "Service status = Running" `
    ($svc -and $svc.Status -eq "Running") `
    $(if ($svc) { "Use: Start-Service $($svc.Name)" } else { "Service not installed" })

# CHECK 3: Log file exists
Write-Host ""
Write-Host "[ CHECK 3 ] Log file" -ForegroundColor White
Write-Check "Log file exists: $logFile" (Test-Path $logFile) "If missing, service may not have initialized logging yet."

# CHECK 4: Enrollment / heartbeat markers
Write-Host ""
Write-Host "[ CHECK 4 ] Enrollment + heartbeat markers (wait up to ${WaitSeconds}s)" -ForegroundColor White

$enrolled = $false
$heartbeats = $false
$deadline = (Get-Date).AddSeconds($WaitSeconds)

while ((Get-Date) -lt $deadline) {
    if (Test-Path $logFile) {
        $raw = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
        if ($raw -match "Enrolled OK") { $enrolled = $true }
        if ($raw -match "Heartbeat (queued|sent)") { $heartbeats = $true }
    }
    if ($enrolled -and $heartbeats) { break }
    Start-Sleep -Seconds 2
}

Write-Check "Log contains enrollment marker" $enrolled "Expected text: 'Enrolled OK'"
Write-Check "Log contains heartbeat marker" $heartbeats "Expected text: 'Heartbeat queued' or 'Heartbeat sent'"

Write-Host ""
Write-Host "[ Last 20 log lines ]" -ForegroundColor DarkGray
if (Test-Path $logFile) {
    Get-Content $logFile -Tail 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
} else {
    Write-Host "  (log file not found)" -ForegroundColor DarkGray
}

# CHECK 5: Optional API round-trip test
if ($SkipJobTest) {
    Write-Host ""
    Write-Host "[ CHECK 5 ] Job test skipped (--SkipJobTest)" -ForegroundColor Yellow
} elseif (-not $AdminEmail -or -not $AdminPassword) {
    Write-Host ""
    Write-Host "[ CHECK 5 ] Job test skipped (missing -AdminEmail / -AdminPassword)" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "[ CHECK 5 ] Backend API job test" -ForegroundColor White
    try {
        $loginBody = @{ email = $AdminEmail; password = $AdminPassword } | ConvertTo-Json
        $loginResp = Invoke-RestMethod -Method POST `
            -Uri "$BackendUrl/api/auth/login" `
            -Body $loginBody `
            -ContentType "application/json"
        $jwt = $loginResp.token
        Write-Check "Backend login" ($null -ne $jwt -and $jwt.Length -gt 20) "JWT acquired"

        if ($jwt) {
            $headers = @{ Authorization = "Bearer $jwt" }
            $agents = Invoke-RestMethod -Method GET -Uri "$BackendUrl/api/agents?limit=100" -Headers $headers
            $agentId = ($agents.data | Where-Object { $_.status -eq "online" } | Select-Object -First 1).id

            Write-Check "Online agent visible in backend" ($null -ne $agentId) `
                $(if ($agentId) { "agent_id=$agentId" } else { "No online agents returned by /api/agents" })

            if ($agentId) {
                $jobBody = @{
                    agent_id = $agentId
                    job_type = "collect_metrics"
                    payload  = @{}
                    reason   = "windows-smoke-test"
                } | ConvertTo-Json -Depth 5

                $jobResp = Invoke-RestMethod -Method POST `
                    -Uri "$BackendUrl/api/jobs" `
                    -Body $jobBody `
                    -ContentType "application/json" `
                    -Headers $headers
                $jobId = $jobResp.id
                Write-Check "Job created" ($null -ne $jobId) "job_id=$jobId"

                if ($jobId) {
                    $jobStatus = ""
                    $jobDeadline = (Get-Date).AddSeconds(60)
                    while ((Get-Date) -lt $jobDeadline) {
                        Start-Sleep -Seconds 3
                        $jobDetail = Invoke-RestMethod -Method GET `
                            -Uri "$BackendUrl/api/jobs/$jobId" `
                            -Headers $headers `
                            -ErrorAction SilentlyContinue
                        $jobStatus = [string]$jobDetail.status
                        if ($jobStatus -in @("completed", "failed", "cancelled")) { break }
                    }
                    Write-Check "Job reached terminal state" ($jobStatus -in @("completed", "failed", "cancelled")) "status=$jobStatus"
                }
            }
        }
    } catch {
        Write-Check "Backend API job test" $false "Exception: $_"
    }
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Results: $Passed passed, $Failed failed" -ForegroundColor $(if ($Failed -eq 0) { "Green" } else { "Red" })
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

if ($Failed -gt 0) {
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Get-Service '$serviceName'" -ForegroundColor DarkYellow
    Write-Host "  2. Get-Content '$logFile' -Tail 50" -ForegroundColor DarkYellow
    Write-Host "  3. & 'C:\Program Files\Reap3r Agent\reap3r-agent.exe' --diagnose" -ForegroundColor DarkYellow
    Write-Host ""
    exit 1
}

Write-Host "All checks passed." -ForegroundColor Green
exit 0
