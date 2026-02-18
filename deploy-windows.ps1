# MASSVISION Reap3r - Windows Deployment Script
# Usage: powershell -ExecutionPolicy Bypass -File deploy-windows.ps1 -VpsIp "72.62.181.194" -VpsUser "root"

param(
    [string]$VpsIp = "72.62.181.194",
    [string]$VpsUser = "root",
    [string]$VpsPassword = "",
    [string]$ProjectDir = "C:\Projects\massvision-reap3r"
)

$ErrorActionPreference = "Stop"

Write-Host "╔════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  MASSVISION Reap3r - VPS Deployment Tool  ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan

if (-not $VpsPassword) {
    $cred = Get-Credential -UserName $VpsUser -Message "Enter VPS credentials"
    $VpsPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($cred.Password))
}

# Method 1: Try SSH key if available
Write-Host "`n[1/3] Checking SSH keys..." -ForegroundColor Yellow
$sshKey = "$env:USERPROFILE\.ssh\id_ed25519"
if (Test-Path $sshKey) {
    Write-Host "✓ SSH key found: $sshKey" -ForegroundColor Green
    Write-Host "[2/3] Attempting SSH deployment..." -ForegroundColor Yellow
    
    $installScript = Get-Content "$ProjectDir\install-prod.sh" -Raw
    
    # Add public key to authorized_keys first
    $pubKey = Get-Content "$sshKey.pub" -Raw
    $setupCmd = @"
mkdir -p ~/.ssh && echo '$pubKey' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo 'Key added successfully'
"@
    
    # Encode and attempt
    try {
        Write-Host "Adding SSH public key to VPS..." -ForegroundColor Cyan
        # Using ssh-keyscan to verify connectivity
        & ssh-keyscan -t ed25519 $VpsIp 2>$null | Add-Content "$env:USERPROFILE\.ssh\known_hosts"
        
        # For now, provide instructions
        Write-Host "`n⚠️  SSH key authentication not yet configured on VPS" -ForegroundColor Yellow
        Write-Host "`nTo enable SSH key access, execute this on VPS manually:" -ForegroundColor Cyan
        Write-Host "────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "mkdir -p ~/.ssh" -ForegroundColor White
        Write-Host "echo '$pubKey' >> ~/.ssh/authorized_keys" -ForegroundColor White
        Write-Host "chmod 600 ~/.ssh/authorized_keys" -ForegroundColor White
        Write-Host "────────────────────────────────────────────────" -ForegroundColor Gray
    }
    catch {
        Write-Host "⚠️  SSH key method unavailable: $_" -ForegroundColor Yellow
    }
}

# Method 2: Git + HTTPS (Recommended over password SSH)
Write-Host "`n[3/3] Alternative: Git-based deployment" -ForegroundColor Yellow
Write-Host "`nTo deploy via Git (recommended):" -ForegroundColor Cyan
Write-Host "────────────────────────────────────────────────" -ForegroundColor Gray
Write-Host "1. Push to GitHub: git push origin main" -ForegroundColor White
Write-Host "2. SSH to VPS: ssh root@$VpsIp" -ForegroundColor White
Write-Host "3. Run on VPS: bash <(curl -sSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/install-prod.sh)" -ForegroundColor White
Write-Host "────────────────────────────────────────────────" -ForegroundColor Gray

# Method 3: Manual installation with script
Write-Host "`nOr use local installation script:" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════" -ForegroundColor Gray
Write-Host "cd $ProjectDir" -ForegroundColor White
Write-Host 'ssh root@$VpsIp "bash -s" < install-prod.sh' -ForegroundColor White
Write-Host "════════════════════════════════════════════════" -ForegroundColor Gray

Write-Host "`n✓ Deployment helper ready!" -ForegroundColor Green
Write-Host "Next: Add SSH key to VPS or push to GitHub for remote deployment" -ForegroundColor Cyan
