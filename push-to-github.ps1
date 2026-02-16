param([string]$GithubUsername)

if (-not $GithubUsername) {
    Write-Host "Usage: .\push-to-github.ps1 -GithubUsername YOUR_USERNAME" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Example:" -ForegroundColor Cyan
    Write-Host "   .\push-to-github.ps1 -GithubUsername john-doe" -ForegroundColor White
    exit 1
}

Clear-Host
$repoUrl = "https://github.com/$GithubUsername/massvision-reap3r.git"

Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║        GitHub Push - Massvision Reap3r        ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

Write-Host "[1/3] Setting remote URL..." -ForegroundColor Yellow
git remote set-url origin $repoUrl
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Remote URL set: $repoUrl" -ForegroundColor Green
}
else {
    Write-Host "✗ Failed to set remote URL" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[2/3] Pushing code to GitHub..." -ForegroundColor Yellow
git push -u origin main
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Code pushed successfully" -ForegroundColor Green
}
else {
    Write-Host "✗ Push failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[3/3] Deploy command for VPS" -ForegroundColor Yellow
Write-Host "───────────────────────────────────────────────" -ForegroundColor Gray
Write-Host "SSH into VPS console and run:" -ForegroundColor White
Write-Host ""
Write-Host "bash <(curl -sSL https://raw.githubusercontent.com/$GithubUsername/massvision-reap3r/main/install-prod.sh)" -ForegroundColor Cyan
Write-Host ""
Write-Host "───────────────────────────────────────────────" -ForegroundColor Gray
Write-Host ""
Write-Host "✓ Ready to deploy!" -ForegroundColor Green
