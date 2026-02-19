# Script de Déploiement MASSVISION Reap3r
# Usage: .\deploy-vps.ps1 -VpsIP 72.62.181.194 -VpsUser root
# Authentification: cle SSH recommandee (ne pas stocker de mots de passe dans les scripts)

param(
    [string]$VpsIP = "72.62.181.194",
    [string]$VpsUser = "root",
    [int]$VpsPort = 22,
    [string]$AppDir = "/app/massvision-reap3r"
)

$ErrorActionPreference = "Stop"

# Couleurs
$colors = @{
    Success = "Green"
    Error   = "Red"
    Warning = "Yellow"
    Info    = "Cyan"
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    $color = if ($colors.ContainsKey($Level)) { $colors[$Level] } else { "White" }
    $prefix = @{
        Success = "[OK]"
        Error   = "[ERR]"
        Warning = "[WARN]"
        Info    = "[INFO]"
    }[$Level]
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Invoke-SSHCommand {
    param(
        [string]$Command
    )
    
    Write-Log "Exécution: $Command" "Info"
    
    # Essayer avec ssh intégré de Windows 10+
    $result = & ssh -o "StrictHostKeyChecking=accept-new" `
                     -p $VpsPort `
                     "$VpsUser@$VpsIP" `
                     $Command 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Erreur SSH: $result" "Error"
        return $null
    }
    
    return $result
}

function Deploy-Backend {
    Write-Log "Déploiement du Backend..." "Info"
    
    $script = @"
#!/bin/bash
set -e
cd $AppDir

ENV_FILE="$AppDir/backend/.env"

# Create once; do NOT rotate JWT/HMAC secrets on redeploy (would break sessions + agents).
if [ ! -f "$ENV_FILE" ]; then
  JWT_SECRET="$(openssl rand -base64 32)"
  HMAC_SECRET="$(openssl rand -base64 32)"
  cat > "$ENV_FILE" <<EOF
NODE_ENV=production
PORT=4000
# Deprecated legacy var kept for migration compatibility.
WS_PORT=4000
API_BASE_URL=http://$($VpsIP)
DATABASE_URL=postgresql://reap3r:reap3r_secret@localhost:5432/reap3r
JWT_SECRET=$JWT_SECRET
HMAC_SECRET=$HMAC_SECRET
LOG_LEVEL=info
EOF
  chmod 600 "$ENV_FILE"
fi

set -a
. "$ENV_FILE"
set +a

# Build (workspace root, so shared packages resolve correctly)
npm ci --workspaces
npm -w backend run build

# Démarrer avec PM2
pm2 delete reap3r-backend 2>/dev/null || true
pm2 start "npm -w backend start" --name reap3r-backend --env production
pm2 save

echo "Backend déployé"
"@
    
    Invoke-SSHCommand $script
    Write-Log "Backend déployé" "Success"
}

function Deploy-Frontend {
    Write-Log "Déploiement du Frontend..." "Info"
    
    $script = @"
#!/bin/bash
set -e
cd $AppDir

# Build: leave API base empty to default to same-origin (/api proxied by Nginx).
NEXT_PUBLIC_API_URL= npm -w frontend run build

# Démarrer avec PM2
pm2 delete reap3r-frontend 2>/dev/null || true
pm2 start "npm -w frontend start" --name reap3r-frontend --env production
pm2 save

echo "Frontend déployé"
"@
    
    Invoke-SSHCommand $script
    Write-Log "Frontend déployé" "Success"
}

function Setup-Database {
    Write-Log "Configuration de PostgreSQL..." "Info"
    
    $script = @"
#!/bin/bash
sudo systemctl start postgresql

# Créer l'utilisateur et la base
sudo -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = 'reap3r'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER reap3r WITH PASSWORD 'reap3r_secret';"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'reap3r'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE reap3r OWNER reap3r;"

# Migrations
export DATABASE_URL="postgresql://reap3r:reap3r_secret@localhost:5432/reap3r"
cd $AppDir/backend
npm run db:migrate

echo "Base de données configurée"
"@
    
    Invoke-SSHCommand $script
    Write-Log "Base de données configurée" "Success"
}

function Setup-Dependencies {
    Write-Log "Installation des dépendances..." "Info"
    
    $script = @"
#!/bin/bash
set -e

# Node.js
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
fi

# PM2
npm install -g pm2
pm2 startup

# PostgreSQL
apt-get install -y postgresql postgresql-contrib

# Nginx
apt-get install -y nginx

echo "Dépendances installées"
"@
    
    Invoke-SSHCommand $script
    Write-Log "Dépendances installées" "Success"
}

function Setup-Nginx {
    Write-Log "Configuration de Nginx..." "Info"
    
    $nginxConfig = @"
upstream backend_http {
    server 127.0.0.1:4000;
}

upstream frontend {
    server 127.0.0.1:3000;
}

server {
    listen 80 default_server;
    server_name _;
    client_max_body_size 100M;

    location /api/ {
        proxy_pass http://backend_http;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Agent WebSocket gateway (unified backend port)
    location /ws/agent {
        proxy_pass http://backend_http;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # UI WebSocket upgrade
    location /ws {
        proxy_pass http://backend_http;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location / {
        proxy_pass http://frontend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
"@
    
    $script = @"
#!/bin/bash
cat > /etc/nginx/sites-available/reap3r <<'EOF'
$nginxConfig
EOF

ln -sf /etc/nginx/sites-available/reap3r /etc/nginx/sites-enabled/reap3r
rm -f /etc/nginx/sites-enabled/default

nginx -t
systemctl restart nginx
systemctl enable nginx

echo "Nginx configuré"
"@
    
    Invoke-SSHCommand $script
    Write-Log "Nginx configuré" "Success"
}

function Clone-Repository {
    Write-Log "Clonage du dépôt..." "Info"
    
    $script = @"
#!/bin/bash
if [ ! -d "$AppDir" ]; then
    mkdir -p /app
    cd /app
    # À remplacer par votre repo Git
    git clone https://github.com/massoce69/reap3r-2.git massvision-reap3r 2>/dev/null || \
    mkdir -p massvision-reap3r
else
    cd "$AppDir"
    git pull origin main 2>/dev/null || true
fi

echo "Dépôt initialisé"
"@
    
    Invoke-SSHCommand $script  
    Write-Log "Dépôt cloné/mis à jour" "Success"
}

# Main deployment workflow
Write-Log "=== MASSVISION Reap3r - Déploiement VPS ===" "Info"
Write-Log "Serveur: $VpsIP (Port: $VpsPort)" "Info"
Write-Log "Utilisateur: $VpsUser" "Info"
Write-Log ""

try {
    # Test de connexion
    Write-Log "Test de connexion..." "Info"
    $testCmd = Invoke-SSHCommand "echo 'OK'"
    if ($null -eq $testCmd) {
        Write-Log "Impossible de se connecter au serveur" "Error"
        exit 1
    }
    Write-Log "Connexion réussie" "Success"
    Write-Log ""
    
    # Étapes de déploiement
    Clone-Repository
    Setup-Dependencies
    Setup-Database
    Setup-Nginx
    Deploy-Backend
    Deploy-Frontend
    
    Write-Log ""
    Write-Log "=== Déploiement terminé! ===" "Success"
    Write-Log "Frontend: http://$VpsIP" "Info"
    Write-Log "API: http://$VpsIP/api/" "Info"
    Write-Log "Logs: ssh $VpsUser@$VpsIP 'pm2 logs'" "Info"
    
} catch {
    Write-Log "Erreur: $_" "Error"
    exit 1
}
