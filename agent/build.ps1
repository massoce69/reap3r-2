# Build MassVision Agent binaries (Windows)
# Produces:
#   agent/dist/agent-x64.exe
#   agent/dist/agent-x86.exe (best-effort)

param(
    [switch]$SkipX86,
    [switch]$SkipX64
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$agentDir = Join-Path $root "agent"
$distDir = Join-Path $agentDir "dist"
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

function Copy-IfExists {
    param(
        [string]$From,
        [string]$To
    )
    if (-not (Test-Path $From)) {
        throw "Expected build output not found: $From"
    }
    Copy-Item -Path $From -Destination $To -Force
}

Push-Location $agentDir
try {
    if (-not $SkipX64) {
        Write-Host "[agent] Building x64..." -ForegroundColor Cyan
        & cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build (x64) failed" }

        $x64From = Join-Path $agentDir "target\release\massvision-agent.exe"
        $x64To = Join-Path $distDir "agent-x64.exe"
        Copy-IfExists -From $x64From -To $x64To
        Write-Host "[agent] x64 -> $x64To" -ForegroundColor Green
    }

    if (-not $SkipX86) {
        Write-Host "[agent] Building x86 (best-effort)..." -ForegroundColor Cyan
        try {
            & cargo build --release --target i686-pc-windows-msvc
            if ($LASTEXITCODE -ne 0) { throw "cargo build (x86) failed" }

            $x86From = Join-Path $agentDir "target\i686-pc-windows-msvc\release\massvision-agent.exe"
            $x86To = Join-Path $distDir "agent-x86.exe"
            Copy-IfExists -From $x86From -To $x86To
            Write-Host "[agent] x86 -> $x86To" -ForegroundColor Green
        } catch {
            Write-Host "[agent] WARN: x86 build skipped/failed: $_" -ForegroundColor Yellow
        }
    }
} finally {
    Pop-Location
}
