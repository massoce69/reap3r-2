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

Write-Host "[1/4] Checking Git repository..." -ForegroundColor Yellow
$gitRemote = git config --get remote.origin.url 2>$null

if (-not $gitRemote) {
    Write-Host "   No remote configured, adding..." -ForegroundColor Gray
    git remote add origin $repoUrl
    Write-Host "   ✓ Remote added" -ForegroundColor Green
}
else {
    Write-Host "   Updating existing remote..." -ForegroundColor Gray
    git remote set-url origin $repoUrl
    Write-Host "   ✓ Remote updated" -ForegroundColor Green
}

Write-Host ""
Write-Host "[2/4] Adding all files..." -ForegroundColor Yellow
git add .
Write-Host "   ✓ Files staged" -ForegroundColor Green

Write-Host ""
Write-Host "[3/4] Committing changes..." -ForegroundColor Yellow
$commitMsg = "Deploy to VPS - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
git commit -m $commitMsg --allow-empty 2>$null
Write-Host "   ✓ Changes committed" -ForegroundColor Green

Write-Host ""
Write-Host "[4/4] Pushing to GitHub..." -ForegroundColor Yellow
git push -u origin main
if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✓ Code pushed successfully" -ForegroundColor Green
}
else {
    Write-Host "   ✗ Push failed - check your GitHub credentials" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "═════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "DEPLOY COMMAND FOR VPS:" -ForegroundColor Yellow
Write-Host "═════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "SSH into your VPS console and run:" -ForegroundColor White
Write-Host ""
Write-Host "bash <(curl -sSL https://raw.githubusercontent.com/$GithubUsername/massvision-reap3r/main/install-prod.sh)" -ForegroundColor Cyan
Write-Host ""
Write-Host "═════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "✓ Ready to deploy!" -ForegroundColor Green
Write-Host ""
