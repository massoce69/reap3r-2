@echo off
REM Script de déploiement VPS MASSVISION Reap3r
REM Exécutez ce fichier depuis Windows PowerShell (en tant qu'administrateur si nécessaire)

setlocal enabledelayedexpansion

echo.
echo ====================================================
echo  MASSVISION Reap3r - Déploiement VPS
echo ====================================================
echo.
echo VPS IP: 72.62.181.194
echo Utilisateur: root
echo.

REM Vérifier si Putty/Plink est disponible
where plink >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] Git Bash est recommandé pour SSH
    echo.
    echo Deux options:
    echo.
    echo Option 1 - Installer Git pour Windows:
    echo   https://gitforwindows.org/
    echo.
    echo Option 2 - Executable directement depuis le VPS:
    echo   ssh root@72.62.181.194
    echo   bash ^<(curl -fsSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/bootstrap.sh^)
    echo.
    pause
    exit /b 1
)

REM User confirmation
set /p confirm="Êtes-vous prêt à déployer sur 72.62.181.194? (Y/N): "
if /i not "!confirm!"=="Y" (
    echo Déploiement annulé.
    pause
    exit /b 0
)

echo.
echo [*] Connexion au VPS...
echo [*] Téléchargement et exécution du script de déploiement...
echo.

REM Exécuter le script bootstrap sur le VPS
plink -ssh -l root 72.62.181.194 "bash -s" ^
    <<EOF
set -e
echo "Clonage du script..."
cd /tmp
curl -fsSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/bootstrap.sh > bootstrap.sh
echo "Exécution du déploiement..."
sudo bash bootstrap.sh
EOF

if !errorlevel! equ 0 (
    echo.
    echo ====================================================
    echo  ✓ Déploiement terminé avec succès!
    echo ====================================================
    echo.
    echo Accédez à votre application:
    echo   Frontend: http://72.62.181.194
    echo   API: http://72.62.181.194/api/
    echo.
    echo Gestion des services:
    echo   ssh root@72.62.181.194
    echo   pm2 status
    echo   pm2 logs
    echo.
) else (
    echo.
    echo ====================================================
    echo  ✗ Erreur lors du déploiement
    echo ====================================================
    echo.
)

pause
