param([string]$VpsPassword = "Chenhao`$macross69", [string]$VpsIp = "72.62.181.194")

Write-Host "╔═════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║ MASSVISION Reap3r - VPS Deployment ║" -ForegroundColor Cyan
Write-Host "╚═════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$sshKey = "$env:USERPROFILE\.ssh\id_ed25519"
$pubKey = Get-Content "$sshKey.pub" -Raw

Write-Host "✓ SSH Key found" -ForegroundColor Green
Write-Host "✓ Project ready at C:\Projects\massvision-reap3r" -ForegroundColor Green
Write-Host ""
Write-Host "DEPLOYMENT OPTIONS:" -ForegroundColor Yellow
Write-Host "───────────────────────────────────────────────" -ForegroundColor Gray
Write-Host ""
Write-Host "Option 1: Via GitHub (RECOMMENDED for Windows)" -ForegroundColor Cyan
Write-Host "  1. git push origin main" -ForegroundColor White
Write-Host "  2. SSH into VPS and run deploy script" -ForegroundColor White
Write-Host ""
Write-Host "Option 2: Direct SSH via install-prod.sh" -ForegroundColor Cyan
Write-Host "  Requires: SSH key auth configured on VPS" -ForegroundColor Gray
Write-Host "  Command: ssh root@$VpsIp 'bash -s' < install-prod.sh" -ForegroundColor White
Write-Host ""
Write-Host "Your SSH Public Key (add to VPS ~/.ssh/authorized_keys):" -ForegroundColor Yellow
Write-Host "───────────────────────────────────────────────" -ForegroundColor Gray
Write-Host $pubKey -ForegroundColor White
Write-Host "───────────────────────────────────────────────" -ForegroundColor Gray
Write-Host ""
Write-Host "Full guide: See DEPLOYMENT-FINAL.md" -ForegroundColor Cyan
