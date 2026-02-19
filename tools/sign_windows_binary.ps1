param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][string]$PfxPath,
    [Parameter(Mandatory = $true)][string]$PfxPassword,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$Description = "MASSVISION Reap3r Agent"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $FilePath)) {
    throw "File not found: $FilePath"
}
if (-not (Test-Path $PfxPath)) {
    throw "PFX not found: $PfxPath"
}

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\**\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending |
    Select-Object -First 1

if (-not $signtool) {
    throw "signtool.exe not found in Windows SDK"
}

& $signtool.FullName sign `
    /fd SHA256 `
    /f $PfxPath `
    /p $PfxPassword `
    /tr $TimestampUrl `
    /td SHA256 `
    /d $Description `
    $FilePath

if ($LASTEXITCODE -ne 0) {
    throw "signtool sign failed for $FilePath"
}

$sig = Get-AuthenticodeSignature -FilePath $FilePath
if ($sig.Status -ne "Valid") {
    throw "Authenticode signature status is '$($sig.Status)' for $FilePath"
}

Write-Host "Signed: $FilePath"
Write-Host "Signer thumbprint: $($sig.SignerCertificate.Thumbprint)"
