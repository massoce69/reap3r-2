# MASSVISION Reap3r - VPS deployment script
# Usage: .\deploy-vps.ps1 -VpsIP 72.62.181.194 -VpsUser root

param(
    [string]$VpsIP = "72.62.181.194",
    [string]$VpsUser = "root",
    [int]$VpsPort = 22,
    [string]$AppDir = "/app/massvision-reap3r",
    [string]$RepoUrl = "https://github.com/massoce69/reap3r-2.git"
)

$ErrorActionPreference = "Stop"

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

    $isScript = $Command.Contains("`n")
    if ($isScript) {
        $result = $Command | & ssh -o "StrictHostKeyChecking=accept-new" `
                                 -p $VpsPort `
                                 "$VpsUser@$VpsIP" `
                                 "bash -s" 2>&1
    } else {
        $result = & ssh -o "StrictHostKeyChecking=accept-new" `
                         -p $VpsPort `
                         "$VpsUser@$VpsIP" `
                         $Command 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Log "SSH command failed:`n$result" "Error"
        return $null
    }

    return $result
}

function Clone-Repository {
    Write-Log "Syncing repository..." "Info"

    $script = @"
#!/bin/bash
set -euo pipefail

if [ ! -d "$AppDir/.git" ]; then
  mkdir -p /app
  cd /app
  git clone "$RepoUrl" massvision-reap3r
else
  cd "$AppDir"
  if [ -n "`$(git status --porcelain)" ]; then
    git stash push -u -m "auto-deploy-`$(date +%Y%m%d-%H%M%S)" || true
  fi
  git fetch origin main
  git checkout -B main origin/main
fi
echo "repo_ok"
"@

    Invoke-SSHCommand $script | Out-Null
    Write-Log "Repository synced" "Success"
}

function Setup-Dependencies {
    Write-Log "Installing dependencies..." "Info"

    $script = @"
#!/bin/bash
set -euo pipefail

if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi

if ! command -v pm2 >/dev/null 2>&1; then
  npm install -g pm2
  pm2 startup || true
fi

apt-get update
apt-get install -y postgresql postgresql-contrib nginx git
echo "deps_ok"
"@

    Invoke-SSHCommand $script | Out-Null
    Write-Log "Dependencies ready" "Success"
}

function Setup-Database {
    Write-Log "Configuring PostgreSQL..." "Info"

    $script = @"
#!/bin/bash
set -euo pipefail

sudo systemctl start postgresql
sudo -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = 'reap3r'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE USER reap3r WITH PASSWORD 'reap3r_secret';"
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'reap3r'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE reap3r OWNER reap3r;"
echo "db_ok"
"@

    Invoke-SSHCommand $script | Out-Null
    Write-Log "Database ready" "Success"
}

function Setup-Nginx {
    Write-Log "Configuring Nginx..." "Info"

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
set -euo pipefail

cat > /etc/nginx/sites-available/reap3r <<'EOF'
$nginxConfig
EOF

ln -sf /etc/nginx/sites-available/reap3r /etc/nginx/sites-enabled/reap3r
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx
systemctl enable nginx
echo "nginx_ok"
"@

    Invoke-SSHCommand $script | Out-Null
    Write-Log "Nginx configured" "Success"
}

function Deploy-Backend {
    Write-Log "Deploying backend..." "Info"

    $script = @"
#!/bin/bash
set -euo pipefail
cd $AppDir

ENV_FILE="$AppDir/backend/.env"

if [ ! -f "$ENV_FILE" ]; then
  JWT_SECRET="`$(openssl rand -base64 32)"
  HMAC_SECRET="`$(openssl rand -base64 32)"
  VAULT_MASTER_KEY="`$(openssl rand -base64 32)"
  cat > "$ENV_FILE" <<EOF
NODE_ENV=production
PORT=4000
WS_PORT=4000
API_BASE_URL=http://$VpsIP
DATABASE_URL=postgresql://reap3r:reap3r_secret@localhost:5432/reap3r
JWT_SECRET=$JWT_SECRET
HMAC_SECRET=$HMAC_SECRET
VAULT_MASTER_KEY=$VAULT_MASTER_KEY
LOG_LEVEL=info
EOF
  chmod 600 "$ENV_FILE"
fi

if ! grep -q '^VAULT_MASTER_KEY=' "$ENV_FILE"; then
  echo "VAULT_MASTER_KEY=`$(openssl rand -base64 32)" >> "$ENV_FILE"
fi

set -a
. "$ENV_FILE"
set +a

npm ci --workspaces
npm -w shared run build
npm -w backend run db:migrate
npm -w backend run build

pm2 delete reap3r-backend 2>/dev/null || true
pm2 start "npm -w backend start" --name reap3r-backend --env production
pm2 save
echo "backend_ok"
"@

    Invoke-SSHCommand $script | Out-Null
    Write-Log "Backend deployed" "Success"
}

function Deploy-Frontend {
    Write-Log "Deploying frontend..." "Info"

    $script = @"
#!/bin/bash
set -euo pipefail
cd $AppDir

NEXT_PUBLIC_API_URL= npm -w frontend run build

pm2 delete reap3r-frontend 2>/dev/null || true
pm2 start "npm -w frontend start" --name reap3r-frontend --env production
pm2 save
echo "frontend_ok"
"@

    Invoke-SSHCommand $script | Out-Null
    Write-Log "Frontend deployed" "Success"
}

Write-Log "=== MASSVISION Reap3r VPS deploy ===" "Info"
Write-Log "Server: $VpsIP:$VpsPort ($VpsUser)" "Info"

try {
    $test = Invoke-SSHCommand "echo OK"
    if ($null -eq $test) {
        throw "SSH connection failed"
    }
    Write-Log "SSH connectivity OK" "Success"

    Clone-Repository
    Setup-Dependencies
    Setup-Database
    Setup-Nginx
    Deploy-Backend
    Deploy-Frontend

    Write-Log "Deployment complete" "Success"
    Write-Log "Frontend: http://$VpsIP" "Info"
    Write-Log "API: http://$VpsIP/api/health" "Info"
    Write-Log "Logs: ssh $VpsUser@$VpsIP 'pm2 logs'" "Info"
}
catch {
    Write-Log "Deployment failed: $_" "Error"
    exit 1
}

