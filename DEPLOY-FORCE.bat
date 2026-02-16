@echo off
chcp 65001 >nul
cls
color 0f

set VPS_IP=72.62.181.194
set VPS_USER=root
set PWD=Chenhao$macross69

echo ===================================================
echo   MASSVISION Reap3r - DEPLOIEMENT AUTOMATIQUE
echo ===================================================
echo.
echo [1] Tentative de connexion au VPS...
echo.
echo ***************************************************
echo * MOT DE PASSE A COPIER : %PWD%
echo ***************************************************
echo.
echo Veuillez COLLER le mot de passe quand demande (Clic Droit).
echo.

ssh -o StrictHostKeyChecking=no %VPS_USER%@%VPS_IP% "bash -s" < install-prod.sh

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERREUR] La connexion a echoue.
    echo Si le mot de passe est refuse, essayez la cle SSH.
    pause
    exit /b 1
)

echo.
echo [SUCCES] Deploiement termine !
pause
