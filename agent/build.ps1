# ════════════════════════════════════════════════════════════════════
#  MASSVISION Reap3r Agent — Multi-Architecture Build Script
#  Builds x64 + x86 static binaries for Windows 7 → Server 2025
#
#  Prerequisites:
#    rustup target add x86_64-pc-windows-msvc
#    rustup target add i686-pc-windows-msvc
#
#  Output:  agent/dist/
#    reap3r-agent-x64.exe   (64-bit)
#    reap3r-agent-x86.exe   (32-bit)
#    checksums.sha256
# ════════════════════════════════════════════════════════════════════

param(
    [switch]$SkipX86,
    [switch]$SkipX64,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Reap3r Agent — Multi-Arch Build" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Ensure Rust toolchain is available
if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Rust/Cargo not found. Install from https://rustup.rs" -ForegroundColor Red
    exit 1
}

$version = (Select-String 'version = "([^"]+)"' Cargo.toml | ForEach-Object { $_.Matches[0].Groups[1].Value })
Write-Host "[*] Building Reap3r Agent v$version" -ForegroundColor Yellow
Write-Host ""

# Create dist directory
$distDir = Join-Path $PSScriptRoot "dist"
if ($Clean -and (Test-Path $distDir)) {
    Remove-Item $distDir -Recurse -Force
}
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

# ── Install targets if not present ──
$targets = @()
if (-not $SkipX64) { $targets += "x86_64-pc-windows-msvc" }
if (-not $SkipX86) { $targets += "i686-pc-windows-msvc" }

foreach ($target in $targets) {
    $installed = rustup target list --installed 2>$null | Select-String $target
    if (-not $installed) {
        Write-Host "[*] Installing target: $target" -ForegroundColor Yellow
        rustup target add $target
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] Failed to add target $target" -ForegroundColor Red
            exit 1
        }
    }
}

# ── Build x64 ──
if (-not $SkipX64) {
    Write-Host "[*] Building x64 (x86_64-pc-windows-msvc)..." -ForegroundColor Yellow
    $env:RUSTFLAGS = "-C target-feature=+crt-static"
    cargo build --release --target x86_64-pc-windows-msvc 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] x64 build failed!" -ForegroundColor Red
        exit 1
    }
    $src = "target\x86_64-pc-windows-msvc\release\reap3r-agent.exe"
    $dst = Join-Path $distDir "reap3r-agent-x64.exe"
    Copy-Item $src $dst -Force
    $size = [math]::Round((Get-Item $dst).Length / 1MB, 2)
    Write-Host "[OK] x64 binary: $dst ($size MB)" -ForegroundColor Green
}

# ── Build x86 (32-bit) ──
if (-not $SkipX86) {
    Write-Host "[*] Building x86 (i686-pc-windows-msvc)..." -ForegroundColor Yellow
    $env:RUSTFLAGS = "-C target-feature=+crt-static"
    cargo build --release --target i686-pc-windows-msvc 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] x86 build failed!" -ForegroundColor Red
        exit 1
    }
    $src = "target\i686-pc-windows-msvc\release\reap3r-agent.exe"
    $dst = Join-Path $distDir "reap3r-agent-x86.exe"
    Copy-Item $src $dst -Force
    $size = [math]::Round((Get-Item $dst).Length / 1MB, 2)
    Write-Host "[OK] x86 binary: $dst ($size MB)" -ForegroundColor Green
}

# ── Generate SHA256 checksums ──
Write-Host ""
Write-Host "[*] Generating checksums..." -ForegroundColor Yellow
$checksumFile = Join-Path $distDir "checksums.sha256"
"# Reap3r Agent v$version — SHA256 Checksums" | Out-File $checksumFile
"# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC)" | Out-File $checksumFile -Append
"" | Out-File $checksumFile -Append

Get-ChildItem $distDir -Filter "*.exe" | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$hash  $($_.Name)" | Out-File $checksumFile -Append
    Write-Host "  $hash  $($_.Name)"
}

# ── Summary ──
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Build complete! Files in: $distDir" -ForegroundColor Green
Write-Host ""
Get-ChildItem $distDir | Format-Table Name, @{N="Size";E={"{0:N2} MB" -f ($_.Length/1MB)}} -AutoSize
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "    1. Copy reap3r-agent-x64.exe to the backend upload/ folder" -ForegroundColor Gray
Write-Host "    2. Or build the installer: iscc installer\reap3r-agent.iss" -ForegroundColor Gray
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
