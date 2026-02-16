@echo off
REM Script de déploiement MASSVISION Reap3r sur VPS
REM Utiliser avec : deploy-vps.bat

setlocal enabledelayedexpansion

set VPS_IP=72.62.181.194
set VPS_USER=root
set VPS_PASS=Chenhao$macross69
set VPS_PORT=22

set DEPLOY_DIR=C:\Projects\massvision-reap3r

echo.
echo ====================================
echo MASSVISION Reap3r - VPS Deployment
echo ====================================
echo.

REM Créer l'identifiant SSH pour Plink
echo.
echo [1] Préparation du déploiement...

REM Copier les fichiers vers le serveur via SFTP
echo [2] Copie des fichiers vers le serveur...

REM Créer un script de déploiement temporary
set TEMP_SCRIPT=%TEMP%\deploy_vps.sh
(
echo #!/bin/bash
echo set -e
echo.
echo # Variables
echo APP_DIR="/app/massvision-reap3r"
echo echo "=== Déploiement MASSVISION Reap3r ==="
echo.
echo # Mettre à jour le système
echo echo "Mise à jour du système..."
echo apt-get update ^&^& apt-get upgrade -y
echo.
echo # Installer Node.js
echo if ! command -v node ^&^> /dev/null; then
echo   curl -fsSL https://deb.nodesource.com/setup_20.x ^| bash -
echo   apt-get install -y nodejs
echo fi
echo.
echo # Installer PM2
echo npm install -g pm2 ^&^& pm2 startup
echo.
echo # Installer PostgreSQL
echo apt-get install -y postgresql postgresql-contrib
echo systemctl enable postgresql
echo systemctl start postgresql
echo.
echo # Cloner ou mettre à jour le repo
echo if [ ! -d "$APP_DIR" ]; then
echo   mkdir -p /app
echo   cd /app
echo   git clone https://github.com/yourusername/reap3r.git massvision-reap3r
echo else
echo   cd "$APP_DIR"
echo   git pull origin main
echo fi
echo.
echo # Installer les dépendances
echo cd "$APP_DIR"
echo npm ci --workspaces
echo.
echo # Configuration d'environnement
echo mkdir -p backend frontend
echo cat ^> backend/.env ^<^< EOF
echo NODE_ENV=production
echo DATABASE_URL=postgresql://reap3r:reap3r_secret@localhost:5432/reap3r
echo JWT_SECRET=$(openssl rand -base64 32^)
echo HMAC_SECRET=$(openssl rand -base64 32^)
echo EOF
echo.
echo cat ^> frontend/.env.local ^<^< EOF
echo NEXT_PUBLIC_API_URL=http://localhost:4000
echo EOF
echo.
echo # Créer la base de données
echo sudo -u postgres psql ^<^< EOF
echo CREATE USER IF NOT EXISTS reap3r WITH PASSWORD 'reap3r_secret';
echo ALTER USER reap3r CREATEDB;
echo EOF
echo.
echo # Migrations
echo export DATABASE_URL="postgresql://reap3r:reap3r_secret@localhost:5432/reap3r"
echo cd "$APP_DIR/backend"
echo npm run db:migrate
echo.
echo # Build
echo npm run build
echo cd "$APP_DIR/frontend"
echo npm run build
echo.
echo # Démarrer avec PM2
echo pm2 stop all ^|^| true
echo cd "$APP_DIR/backend"
echo pm2 start --name reap3r-backend --env production npm -- run start
echo cd "$APP_DIR/frontend"
echo pm2 start --name reap3r-frontend --env production npm -- start
echo pm2 save
echo.
echo echo "✓ Déploiement terminé!"
echo pm2 status
) > !TEMP_SCRIPT!

echo [3] Exécution du déploiement sur le serveur...

REM Utiliser plink (Putty) si disponible, sinon utiliser sshpass
where plink >nul 2>&1
if !errorlevel! equ 0 (
    echo Utilisation de Plink...
    REM Cette approche nécessite une clé SSH configurée
    plink -ssh -l !VPS_USER! -P !VPS_PORT! !VPS_IP! -m !TEMP_SCRIPT!
) else (
    where sshpass >nul 2>&1
    if !errorlevel! equ 0 (
        echo Utilisation de sshpass...
        sshpass -p "!VPS_PASS!" ssh -o StrictHostKeyChecking=no -P !VPS_PORT! !VPS_USER!@!VPS_IP! "bash -" ^< !TEMP_SCRIPT!
    ) else (
        echo.
        echo ERREUR: Installez Putty (plink^) ou sshpass pour continuer.
        echo.
        echo Pour Windows:
        echo   - Installer Git Bash qui inclut ssh
        echo   - Ou installer Putty: https://www.putty.org/
        echo.
        pause
        exit /b 1
    )
)

echo.
echo ====================================
echo ✓ Déploiement terminé!
echo ====================================
echo.
echo Accédez à: http://!VPS_IP!
echo API: http://!VPS_IP!/api
echo.
pause
