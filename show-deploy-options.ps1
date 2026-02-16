Clear-Host
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MASSVISION Reap3r - VPS Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "APPLICATION STATUS:" -ForegroundColor Green
Write-Host "  [✓] Backend:  Ready (Fastify)" -ForegroundColor Green
Write-Host "  [✓] Frontend: Ready (Next.js)" -ForegroundColor Green
Write-Host "  [✓] Database: Ready (PostgreSQL)" -ForegroundColor Green
Write-Host "  [✓] Git Repo: Ready (10 commits)" -ForegroundColor Green
Write-Host ""

Write-Host "VPS CONFIGURATION:" -ForegroundColor Yellow
Write-Host "  IP:   72.62.181.194" -ForegroundColor Yellow
Write-Host "  User: root" -ForegroundColor Yellow
Write-Host ""

Write-Host "DEPLOYMENT OPTIONS:" -ForegroundColor Cyan
Write-Host "========================================"  -ForegroundColor Gray
Write-Host ""
Write-Host "OPTION 1: Via GitHub (Recommended)" -ForegroundColor White
Write-Host "  - No password needed" -ForegroundColor Gray
Write-Host "  - Most secure method" -ForegroundColor Gray
Write-Host "  - Push code, deploy from VPS console" -ForegroundColor Gray
Write-Host ""
Write-Host "  Steps:" -ForegroundColor White
Write-Host "    1. Set GitHub URL: git remote set-url origin https://github.com/YOUR_USERNAME/massvision-reap3r.git" -ForegroundColor White
Write-Host "    2. git push origin main" -ForegroundColor White
Write-Host "    3. SSH to VPS console" -ForegroundColor White
Write-Host "    4. bash <(curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/massvision-reap3r/main/install-prod.sh)" -ForegroundColor White
Write-Host ""

Write-Host "OPTION 2: Direct SSH (After SSH key setup)" -ForegroundColor White
Write-Host "  - Requires SSH key on VPS" -ForegroundColor Gray
Write-Host "  - Fully automated from Windows" -ForegroundColor Gray
Write-Host ""
Write-Host "  Setup (on VPS console first):" -ForegroundColor White
$sshKey = Get-Content "$env:USERPROFILE\.ssh\id_ed25519.pub" -Raw
Write-Host "    mkdir -p ~/.ssh" -ForegroundColor White
Write-Host "    echo '$sshKey' >> ~/.ssh/authorized_keys" -ForegroundColor White
Write-Host "    chmod 600 ~/.ssh/authorized_keys" -ForegroundColor White
Write-Host ""
Write-Host "  Then deploy:" -ForegroundColor White
Write-Host "    ssh root@72.62.181.194 'bash -s' < C:\Projects\massvision-reap3r\install-prod.sh" -ForegroundColor White
Write-Host ""

Write-Host "YOUR SSH PUBLIC KEY:" -ForegroundColor Cyan
Write-Host "========================================"  -ForegroundColor Gray
Write-Host $sshKey -ForegroundColor White
Write-Host "========================================"  -ForegroundColor Gray
Write-Host ""

Write-Host "DEPLOYMENT SCRIPTS AVAILABLE:" -ForegroundColor Yellow
Get-ChildItem C:\Projects\massvision-reap3r\*.sh, C:\Projects\massvision-reap3r\deploy-* -ErrorAction SilentlyContinue | Select-Object Name | Format-List -Property @{Name="Script"; Expression={$_.Name}}

Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Cyan
Write-Host "  1. Choose option above (GitHub recommended)" -ForegroundColor White
Write-Host "  2. Follow the setup steps" -ForegroundColor White
Write-Host "  3. Deployment will take 5-10 minutes" -ForegroundColor White
Write-Host ""
Write-Host "For detailed guide, see: DEPLOYMENT-FINAL.md" -ForegroundColor Gray
Write-Host ""
