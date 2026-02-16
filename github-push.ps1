param([string]$GithubUsername)

if (-not $GithubUsername) {
    Write-Host "Usage: deploy-github.ps1 -GithubUsername YOUR_USERNAME"
    exit 1
}

$repoUrl = "https://github.com/$GithubUsername/massvision-reap3r.git"

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "GitHub Deployment - Massvision Reap3r" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

Write-Host "Step 1: Checking Git repository..." -ForegroundColor Yellow
$gitRemote = git config --get remote.origin.url 2>$null

if (-not $gitRemote) {
    Write-Host "  Adding remote..." -ForegroundColor Gray
    git remote add origin $repoUrl
}
else {
    Write-Host "  Updating remote..." -ForegroundColor Gray
    git remote set-url origin $repoUrl
}

Write-Host ""
Write-Host "Step 2: Staging files..." -ForegroundColor Yellow
git add .

Write-Host ""
Write-Host "Step 3: Committing..." -ForegroundColor Yellow
$msg = "Deployment $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
git commit -m $msg --allow-empty 2>$null

Write-Host ""
Write-Host "Step 4: Pushing to GitHub..." -ForegroundColor Yellow

$currentBranch = git rev-parse --abbrev-ref HEAD
Write-Host "  Current branch: $currentBranch" -ForegroundColor Gray

git push -u origin $currentBranch

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Push failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "SUCCESS!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next: Deploy to VPS" -ForegroundColor Cyan
Write-Host "SSH into VPS console and run:" -ForegroundColor White
Write-Host ""

$deployBranch = git rev-parse --abbrev-ref HEAD
$deployUrl = "https://raw.githubusercontent.com/$GithubUsername/massvision-reap3r/$deployBranch/install-prod.sh"

Write-Host "bash <(curl -sSL $deployUrl)" -ForegroundColor Cyan
Write-Host ""
