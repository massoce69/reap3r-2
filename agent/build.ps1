param(
    [switch]$SkipX86,
    [switch]$SkipX64,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Set-Location $PSScriptRoot

function Write-Info([string]$Message) {
    Write-Host "[*] $Message" -ForegroundColor Yellow
}

function Write-Ok([string]$Message) {
    Write-Host "[OK] $Message" -ForegroundColor Green
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo not found. Install Rust from https://rustup.rs"
}

if ($SkipX64 -and $SkipX86) {
    throw "Nothing to build: both -SkipX64 and -SkipX86 were set."
}

function Ensure-Target([string]$Target) {
    $installed = rustup target list --installed 2>$null
    if ($installed -notcontains $Target) {
        Write-Info "Installing Rust target $Target"
        rustup target add $Target
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to install Rust target $Target"
        }
    }
}

function Resolve-CompiledAgentBinary([string]$TargetTriple) {
    $candidates = @(
        "target\$TargetTriple\release\xefi-agent-2.exe",
        "target\$TargetTriple\release\reap3r-agent.exe"
    ) | Where-Object { Test-Path $_ }

    if ($candidates.Count -eq 0) {
        throw "No compiled binary found for target $TargetTriple"
    }

    return $candidates |
        Sort-Object { (Get-Item $_).LastWriteTimeUtc } -Descending |
        Select-Object -First 1
}

function Build-AgentTarget(
    [string]$TargetTriple,
    [string]$PrimaryOutputName,
    [string]$LegacyOutputName,
    [string]$DistDir
) {
    Ensure-Target $TargetTriple
    Write-Info "Building $TargetTriple (static CRT)"
    $env:RUSTFLAGS = "-C target-feature=+crt-static"
    cargo build --release --target $TargetTriple
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed for target $TargetTriple"
    }

    $source = Resolve-CompiledAgentBinary $TargetTriple
    $primaryOut = Join-Path $DistDir $PrimaryOutputName
    $legacyOut = Join-Path $DistDir $LegacyOutputName
    Copy-Item $source $primaryOut -Force
    Copy-Item $source $legacyOut -Force

    $sizeMb = [Math]::Round((Get-Item $primaryOut).Length / 1MB, 2)
    Write-Ok "$PrimaryOutputName ($sizeMb MB) from $source"
}

$versionMatch = Select-String -Path "Cargo.toml" -Pattern '^version\s*=\s*"([^"]+)"'
$version = if ($versionMatch) { $versionMatch.Matches[0].Groups[1].Value } else { "unknown" }
Write-Host "Reap3r agent build - version $version" -ForegroundColor Cyan

$distDir = Join-Path $PSScriptRoot "dist"
if ($Clean -and (Test-Path $distDir)) {
    Remove-Item $distDir -Recurse -Force
}
New-Item -Path $distDir -ItemType Directory -Force | Out-Null

if (-not $SkipX64) {
    Build-AgentTarget `
        -TargetTriple "x86_64-pc-windows-msvc" `
        -PrimaryOutputName "agent-x64.exe" `
        -LegacyOutputName "reap3r-agent-x64.exe" `
        -DistDir $distDir
}

if (-not $SkipX86) {
    Build-AgentTarget `
        -TargetTriple "i686-pc-windows-msvc" `
        -PrimaryOutputName "agent-x86.exe" `
        -LegacyOutputName "reap3r-agent-x86.exe" `
        -DistDir $distDir
}

$checksumFile = Join-Path $distDir "checksums.sha256"
$header = @(
    "# Reap3r Agent $version checksums"
    "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    ""
)
$header | Set-Content -Path $checksumFile -Encoding Ascii

Get-ChildItem -Path $distDir -Filter "*.exe" |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
        "$hash  $($_.Name)" | Add-Content -Path $checksumFile -Encoding Ascii
    }

Write-Host ""
Write-Ok "Build complete. Artifacts:"
Get-ChildItem -Path $distDir | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
