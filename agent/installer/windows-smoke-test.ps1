<#
.SYNOPSIS
    MASSVISION Reap3r Agent — Windows Smoke Test
.DESCRIPTION
    Verifies the agent is installed, running, and has successfully enrolled + sent heartbeats.
    Optionally dispatches a test "ping" job via the backend API and verifies completion.
.PARAMETER BackendUrl
    Base URL of the Reap3r backend REST API (default: http://localhost:4000)
.PARAMETER AdminEmail
    Admin email for backend API auth (to dispatch test job)
.PARAMETER AdminPassword
    Admin password for backend API auth
.PARAMETER WaitSeconds
    How long to wait for initial enrollment (default: 30)
.PARAMETER SkipJobTest
    Skip the job dispatch test (only check service + logs)
.EXAMPLE
    .\windows-smoke-test.ps1 -BackendUrl https://reap3r.example.com -AdminEmail admin@example.com -AdminPassword "P@ss"
.EXAMPLE
    .\windows-smoke-test.ps1 -SkipJobTest
#>
param(
    [string]$BackendUrl    = "http://localhost:4000",
    [string]$AdminEmail    = "",
    [string]$AdminPassword = "",
    [int]$WaitSeconds      = 30,
    [switch]$SkipJobTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$ServiceName = "ReaP3rAgent"
$LogFile     = "C:\ProgramData\Reap3r\logs\agent.log"
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

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Reap3r Agent — Windows Smoke Test"                     -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"             -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# ─── CHECK 1: Service exists ──────────────────────────────────────────────────
Write-Host "[ CHECK 1 ] Service installed" -ForegroundColor White
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
Write-Check "Service '$ServiceName' exists" `
    ($null -ne $svc) `
    $(if ($svc) { "Status: $($svc.Status)" } else { "Not found — run install-windows.ps1 first" })

# ─── CHECK 2: Service running ─────────────────────────────────────────────────
Write-Host ""
Write-Host "[ CHECK 2 ] Service running" -ForegroundColor White
Write-Check "Service status = Running" `
    ($svc -and $svc.Status -eq 'Running') `
    $(if ($svc) { "Use: Start-Service $ServiceName" } else { "Service not installed" })

# ─── CHECK 3: Log file exists ─────────────────────────────────────────────────
Write-Host ""
Write-Host "[ CHECK 3 ] Log file" -ForegroundColor White
Write-Check "Log file exists: $LogFile" (Test-Path $LogFile) "If missing, service may have crashed on start"

# ─── CHECK 4: Wait for enrollment ─────────────────────────────────────────────
Write-Host ""
Write-Host "[ CHECK 4 ] Enrolled OK (waiting up to ${WaitSeconds}s)" -ForegroundColor White

$Enrolled   = $false
$Heartbeats = $false
$Deadline   = (Get-Date).AddSeconds($WaitSeconds)

while ((Get-Date) -lt $Deadline) {
    if (Test-Path $LogFile) {
        $logContent = Get-Content $LogFile -Raw -ErrorAction SilentlyContinue
        if ($logContent -match 'Enrolled OK') { $Enrolled = $true }
        if ($logContent -match 'Heartbeat sent') { $Heartbeats = $true }
    }
    if ($Enrolled -and $Heartbeats) { break }
    Start-Sleep -Seconds 2
    Write-Host "    ... waiting ($([int]($Deadline - (Get-Date)).TotalSeconds)s remaining)" -ForegroundColor DarkGray
}

Write-Check "Log contains 'Enrolled OK'" $Enrolled "Check $LogFile for enrollment errors"
Write-Check "Log contains 'Heartbeat sent'" $Heartbeats "Agent must enroll first, then send heartbeats"

# Show last 20 log lines for context
Write-Host ""
Write-Host "[ Last 20 log lines ]" -ForegroundColor DarkGray
if (Test-Path $LogFile) {
    Get-Content $LogFile -Tail 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
} else {
    Write-Host "  (log file not found)" -ForegroundColor DarkGray
}

# ─── CHECK 5: Job test (optional) ────────────────────────────────────────────
if ($SkipJobTest) {
    Write-Host ""
    Write-Host "[ CHECK 5 ] Job test SKIPPED (--SkipJobTest)" -ForegroundColor Yellow
} elseif (-not $AdminEmail -or -not $AdminPassword) {
    Write-Host ""
    Write-Host "[ CHECK 5 ] Job test SKIPPED (no -AdminEmail / -AdminPassword)" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "[ CHECK 5 ] Dispatch test job via backend API" -ForegroundColor White

    try {
        # Login
        $loginBody = @{ email = $AdminEmail; password = $AdminPassword } | ConvertTo-Json
        $loginResp = Invoke-RestMethod -Method POST `
            -Uri "$BackendUrl/api/auth/login" `
            -Body $loginBody `
            -ContentType "application/json"
        $jwt = $loginResp.token
        Write-Check "Backend login" ($null -ne $jwt) "JWT obtained"

        if ($jwt) {
            $headers = @{ Authorization = "Bearer $jwt" }

            # Get first online agent
            $agents = Invoke-RestMethod -Method GET `
                -Uri "$BackendUrl/api/agents" `
                -Headers $headers
            $agentId = ($agents.agents | Where-Object { $_.status -eq 'online' } | Select-Object -First 1).id

            Write-Check "Agent visible in backend (status=online)" ($null -ne $agentId) `
                $(if ($agentId) { "agent_id=$agentId" } else { "No online agents found — check enrollment" })

            if ($agentId) {
                # Dispatch a collect_metrics job
                $jobBody = @{
                    agent_id = $agentId
                    name     = "collect_metrics"
                    args     = @{}
                } | ConvertTo-Json
                $jobResp = Invoke-RestMethod -Method POST `
                    -Uri "$BackendUrl/api/jobs" `
                    -Body $jobBody `
                    -ContentType "application/json" `
                    -Headers $headers
                $jobId = $jobResp.id

                Write-Check "Job dispatched" ($null -ne $jobId) "job_id=$jobId"

                if ($jobId) {
                    # Poll for completion (max 60s)
                    $jobDone     = $false
                    $jobStatus   = ""
                    $jobDeadline = (Get-Date).AddSeconds(60)
                    while ((Get-Date) -lt $jobDeadline) {
                        Start-Sleep -Seconds 3
                        $jobDetail = Invoke-RestMethod -Method GET `
                            -Uri "$BackendUrl/api/jobs/$jobId" `
                            -Headers $headers -ErrorAction SilentlyContinue
                        $jobStatus = $jobDetail.status
                        if ($jobStatus -in @('completed', 'failed', 'timeout')) { $jobDone = $true; break }
                        Write-Host "    ... job status: $jobStatus" -ForegroundColor DarkGray
                    }
                    Write-Check "Job completed (status=$jobStatus)" ($jobStatus -eq 'completed') `
                        "Expected: completed. If 'failed', check agent logs."
                }
            }
        }
    } catch {
        Write-Check "Backend job test" $false "Exception: $_"
    }
}

# ─── RESULT ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Results: $Passed passed, $Failed failed" -ForegroundColor $(if ($Failed -eq 0) { 'Green' } else { 'Red' })
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($Failed -gt 0) {
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Check service:  Get-Service $ServiceName" -ForegroundColor DarkYellow
    Write-Host "  2. Check events:   Get-EventLog -LogName Application -Source $ServiceName -Newest 10" -ForegroundColor DarkYellow
    Write-Host "  3. Check log:      Get-Content '$LogFile' -Tail 50" -ForegroundColor DarkYellow
    Write-Host "  4. Run diagnose:   & 'C:\Program Files\Reap3r Agent\reap3r-agent.exe' --diagnose" -ForegroundColor DarkYellow
    Write-Host ""
    exit 1
} else {
    Write-Host "All checks passed. Agent is enrolled and sending heartbeats." -ForegroundColor Green
    exit 0
}
