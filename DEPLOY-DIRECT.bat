@echo off
setlocal
chcp 65001 >nul
cls
color 0f

set VPS_IP=72.62.181.194
set VPS_USER=root

echo.
echo =========================================================
echo   MASSVISION Reap3r - DÉPLOIEMENT DIRECT (SANS GITHUB)
echo =========================================================
echo.
echo Cette méthode envoie DIRECTEMENT vos fichiers au VPS via SSH.
echo.
echo Utilisez une cle SSH (recommande). Ce script n'embarque aucun mot de passe.
echo.
echo [1] Compression et Envoi des fichiers...
echo     (Cela peut prendre une minute...)
echo.
echo.

tar --exclude node_modules --exclude .next --exclude .git --exclude .vscode -cf - . | ssh -o StrictHostKeyChecking=no %VPS_USER%@%VPS_IP% "mkdir -p /app/massvision-reap3r && tar xf - -C /app/massvision-reap3r && cd /app/massvision-reap3r && chmod +x install-prod.sh && bash install-prod.sh"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERREUR] Echec de la connexion ou du déploiement.
    echo Verifiez la connexion SSH (cle) et les droits.
    pause
    exit /b 1
)

echo.
echo [SUCCES] Deploiement termine !
echo Acceder a l'application : http://%VPS_IP%
pause
