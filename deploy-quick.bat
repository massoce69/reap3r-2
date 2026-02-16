@echo off
REM MASSVISION Reap3r - Quick VPS Deployment via GitHub
REM Usage: deploy-quick.bat [github-url]

setlocal enabledelayedexpansion

cls
echo.
echo ============================================
echo   MASSVISION Reap3r - VPS Deployment
echo ============================================
echo.

set VPS_IP=72.62.181.194
set GITHUB_URL=%1

if "%GITHUB_URL%"=="" (
    echo ERROR: Please provide GitHub repository URL
    echo.
    echo Usage: deploy-quick.bat https://github.com/username/massvision-reap3r
    echo.
    exit /b 1
)

echo [1/3] Verifying GitHub access...
cd /d C:\Projects\massvision-reap3r
git status >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git repository not initialized
    exit /b 1
)
echo OK - Git repository ready

echo.
echo [2/3] Pushing to GitHub...
git push origin main
if errorlevel 1 (
    echo ERROR: Failed to push to GitHub
    exit /b 1
)
echo OK - Code pushed

echo.
echo [3/3] Deployment Instructions
echo ============================================
echo.
echo SSH into VPS and run ONE of these commands:
echo.
echo Method A - Using curl (EASIEST):
echo   bash ^<(curl -sSL %GITHUB_URL%/raw/main/install-prod.sh)
echo.
echo Method B - Manual approach:
echo   cd /tmp
echo   git clone %GITHUB_URL%
echo   cd massvision-reap3r
echo   bash install-prod.sh
echo.
echo ============================================
echo.
echo Ready! Now:
echo  1. SSH to VPS: ssh root@%VPS_IP%
echo  2. Run the deploy command above
echo.
