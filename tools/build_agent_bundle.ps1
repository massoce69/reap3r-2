# Reap3r enterprise bundle builder (Windows)
# Produces:
#   dist/Reap3rAgentBundle/
#     agent-x64.exe
#     agent-x86.exe
#     installer.exe
#     install.ps1
#     uninstall.ps1
#     config.json
#     logs/

param(
    [string]$OutDir = "dist/Reap3rAgentBundle",
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$bundleDir = Join-Path $root $OutDir
New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $bundleDir "logs") -Force | Out-Null

function Resolve-AgentBinary {
    param(
        [string[]]$Candidates
    )
    foreach ($candidate in $Candidates) {
        $full = Join-Path $root $candidate
        if (Test-Path $full) { return (Resolve-Path $full).Path }
    }
    return $null
}

$x64 = Resolve-AgentBinary @(
    "agent\target\x86_64-pc-windows-msvc\release\reap3r-agent.exe",
    "agent\dist\reap3r-agent-x64.exe"
)
$x86 = Resolve-AgentBinary @(
    "agent\target\i686-pc-windows-msvc\release\reap3r-agent.exe",
    "agent\dist\reap3r-agent-x86.exe"
)

if (-not $x64) { throw "x64 agent binary not found. Build x64 target first." }
if (-not $x86) { throw "x86 agent binary not found. Build x86 target first." }

Copy-Item $x64 (Join-Path $bundleDir "agent-x64.exe") -Force
Copy-Item $x86 (Join-Path $bundleDir "agent-x86.exe") -Force

# Installer executable: current installer flow is CLI-driven (--install) using the same binary.
Copy-Item $x64 (Join-Path $bundleDir "installer.exe") -Force

$installScriptSrc = Join-Path $root "agent\installer\install-windows.ps1"
if (-not (Test-Path $installScriptSrc)) { throw "Install script not found: $installScriptSrc" }
Copy-Item $installScriptSrc (Join-Path $bundleDir "install.ps1") -Force

$uninstallScriptPath = Join-Path $bundleDir "uninstall.ps1"
@'
param(
    [string]$ServiceName = "ReaP3rAgent",
    [string]$InstallDir = "C:\Program Files\Reap3r Agent"
)
$ErrorActionPreference = "SilentlyContinue"
Stop-Service -Name $ServiceName -Force
sc.exe delete $ServiceName | Out-Null
Remove-Item "$InstallDir\reap3r-agent.exe" -Force
Write-Host "Reap3r Agent uninstalled."
'@ | Set-Content -Path $uninstallScriptPath -Encoding UTF8

$configPath = Join-Path $bundleDir "config.json"
$config = @{
    version = $Version
    service_name = "ReaP3rAgent"
    install_dir = "C:\Program Files\Reap3r Agent"
    data_dir = "C:\ProgramData\Reap3r"
    default_server = "wss://your-server.example.com/ws/agent"
    enrollment_token = ""
    notes = "Set enrollment_token only for bootstrap automation. Do not store long-term secrets here."
}
$config | ConvertTo-Json -Depth 5 | Set-Content -Path $configPath -Encoding UTF8

$hashFile = Join-Path $bundleDir "checksums.sha256"
Get-ChildItem $bundleDir -File | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$hash  $($_.Name)"
} | Set-Content -Path $hashFile -Encoding UTF8

Write-Host "Bundle created: $bundleDir"
