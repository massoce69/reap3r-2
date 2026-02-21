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
# Native tools (ssh/git/apt) often write progress on stderr even on success.
# Disable PS7 behavior that promotes native stderr to terminating errors.
$global:PSNativeCommandUseErrorActionPreference = $false

$colors = @{
    Success = "Green"
    Error   = "Red"
    Warning = "Yellow"
    Info    = "Cyan"
}

function New-RandomSecret {
    param([int]$Length = 32)

    $alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }

    $chars = for ($i = 0; $i -lt $Length; $i++) {
        $alphabet[$bytes[$i] % $alphabet.Length]
    }
    return (-join $chars)
}

$DbPassword = New-RandomSecret -Length 24
$DeployCallbackKey = New-RandomSecret -Length 48

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

    $scriptText = if ($Command.Contains("`n")) {
        $Command
    } else {
        "#!/bin/bash`nset -e`n$Command`n"
    }

    $tmpFile = [System.IO.Path]::GetTempFileName()
    $oldErrorPreference = $global:ErrorActionPreference
    try {
        $global:ErrorActionPreference = "Continue"
        Set-Content -Path $tmpFile -Value $scriptText -Encoding Ascii -NoNewline

        $sshCmd = "type `"$tmpFile`" | ssh -o StrictHostKeyChecking=accept-new -p $VpsPort $VpsUser@$VpsIP bash -s"
        $result = & cmd.exe /d /s /c $sshCmd 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $global:ErrorActionPreference = $oldErrorPreference
        Remove-Item -Path $tmpFile -Force -ErrorAction SilentlyContinue
    }

    if ($exitCode -ne 0) {
        Write-Log "SSH command failed (code $exitCode):`n$result" "Error"
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

    $res = Invoke-SSHCommand $script
    if ($null -eq $res) { throw "Clone-Repository failed" }
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
apt-get install -y postgresql postgresql-contrib nginx git openssl
echo "deps_ok"
"@

    $res = Invoke-SSHCommand $script
    if ($null -eq $res) { throw "Setup-Dependencies failed" }
    Write-Log "Dependencies ready" "Success"
}

function Setup-Database {
    Write-Log "Configuring PostgreSQL..." "Info"

    $script = @"
#!/bin/bash
set -euo pipefail

DB_PASS="$DbPassword"
ENV_FILE="$AppDir/backend/.env"

if [ -f "`$ENV_FILE" ]; then
  DB_URL_LINE="`$(grep -E '^DATABASE_URL=' "`$ENV_FILE" | head -n1 || true)"
  if [ -n "`$DB_URL_LINE" ]; then
    DB_URL="`$(printf '%s' "`$DB_URL_LINE" | cut -d= -f2-)"
    PARSED_PASS="`$(printf '%s' "`$DB_URL" | sed -E 's#^[^:]+://[^:]+:([^@]+)@.*#\1#' || true)"
    if [ -n "`$PARSED_PASS" ] && [ "`$PARSED_PASS" != "`$DB_URL" ]; then
      DB_PASS="`$PARSED_PASS"
    fi
  fi
fi

sudo systemctl start postgresql
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname = 'reap3r'" | grep -q 1; then
  sudo -u postgres psql -c "CREATE USER reap3r WITH PASSWORD '`$DB_PASS';"
else
  sudo -u postgres psql -c "ALTER USER reap3r WITH PASSWORD '`$DB_PASS';"
fi
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'reap3r'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE reap3r OWNER reap3r;"
echo "db_ok"
"@

    $res = Invoke-SSHCommand $script
    if ($null -eq $res) { throw "Setup-Database failed" }
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
    listen 80;
    server_name _;
    client_max_body_size 100M;

    location /api/ {
        proxy_pass http://backend_http;
        proxy_http_version 1.1;
        proxy_set_header Upgrade `$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host `$host;
        proxy_set_header X-Real-IP `$remote_addr;
        proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto `$scheme;
    }

    location /ws/agent {
        proxy_pass http://backend_http;
        proxy_http_version 1.1;
        proxy_set_header Upgrade `$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host `$host;
        proxy_set_header X-Real-IP `$remote_addr;
        proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto `$scheme;
    }

    location /ws {
        proxy_pass http://backend_http;
        proxy_http_version 1.1;
        proxy_set_header Upgrade `$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host `$host;
        proxy_set_header X-Real-IP `$remote_addr;
        proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto `$scheme;
    }

    location / {
        proxy_pass http://frontend;
        proxy_http_version 1.1;
        proxy_set_header Host `$host;
        proxy_set_header X-Real-IP `$remote_addr;
        proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto `$scheme;
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

    $res = Invoke-SSHCommand $script
    if ($null -eq $res) { throw "Setup-Nginx failed" }
    Write-Log "Nginx configured" "Success"
}

function Deploy-AgentBinaries {
    Write-Log "Preparing agent binaries..." "Info"

    $distDir = Join-Path $PSScriptRoot "agent\dist"
    $x64 = Join-Path $distDir "agent-x64.exe"
    $x86 = Join-Path $distDir "agent-x86.exe"

    if (-not (Test-Path $x64) -or -not (Test-Path $x86)) {
        Write-Log "agent/dist binaries missing; building locally..." "Warning"
        & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "agent\build.ps1")
        if ($LASTEXITCODE -ne 0) {
            throw "Local agent build failed"
        }
    }

    $mkdir = Invoke-SSHCommand @"
#!/bin/bash
set -euo pipefail
mkdir -p "$AppDir/agent/dist"
echo "agent_dist_ready"
"@
    if ($null -eq $mkdir) { throw "Failed to prepare remote agent/dist directory" }

    $scpCmd = "scp -o StrictHostKeyChecking=accept-new -P $VpsPort `"$x64`" `"$x86`" ${VpsUser}@${VpsIP}:`"$AppDir/agent/dist/`""
    & cmd.exe /d /s /c $scpCmd 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to upload agent binaries with scp"
    }

    Write-Log "Agent binaries uploaded to $AppDir/agent/dist" "Success"
}

function Deploy-Backend {
    Write-Log "Deploying backend..." "Info"

    $script = @"
#!/bin/bash
set -euo pipefail
cd $AppDir

ENV_FILE="$AppDir/backend/.env"

if [ ! -f "`$ENV_FILE" ]; then
  JWT_SECRET="`$(openssl rand -base64 32)"
  HMAC_SECRET="`$(openssl rand -base64 32)"
  VAULT_MASTER_KEY="`$(openssl rand -base64 32)"
  cat > "`$ENV_FILE" <<EOF
NODE_ENV=production
PORT=4000
WS_PORT=4000
API_BASE_URL=http://$VpsIP
DATABASE_URL=postgresql://reap3r:$DbPassword@localhost:5432/reap3r
JWT_SECRET=`$JWT_SECRET
HMAC_SECRET=`$HMAC_SECRET
VAULT_MASTER_KEY=`$VAULT_MASTER_KEY
DEPLOY_CALLBACK_KEY=$DeployCallbackKey
LOG_LEVEL=info
AGENT_UPDATE_RETRY_COUNT=2
AGENT_UPDATE_RETRY_BACKOFF_MS=1500
AGENT_UPDATE_DEFER_SECONDS=0
AGENT_UPDATE_JITTER_MAX_SECONDS=60
AGENT_UPDATE_SELF_RESTART_DELAY_SECONDS=6
EOF
  chmod 600 "`$ENV_FILE"
fi

if ! grep -q '^VAULT_MASTER_KEY=' "`$ENV_FILE"; then
  echo "VAULT_MASTER_KEY=`$(openssl rand -base64 32)" >> "`$ENV_FILE"
fi

if ! grep -q '^DEPLOY_CALLBACK_KEY=' "`$ENV_FILE"; then
  echo "DEPLOY_CALLBACK_KEY=$DeployCallbackKey" >> "`$ENV_FILE"
fi

if ! grep -q '^AGENT_UPDATE_RETRY_COUNT=' "`$ENV_FILE"; then
  echo "AGENT_UPDATE_RETRY_COUNT=2" >> "`$ENV_FILE"
fi

if ! grep -q '^AGENT_UPDATE_RETRY_BACKOFF_MS=' "`$ENV_FILE"; then
  echo "AGENT_UPDATE_RETRY_BACKOFF_MS=1500" >> "`$ENV_FILE"
fi

if ! grep -q '^AGENT_UPDATE_DEFER_SECONDS=' "`$ENV_FILE"; then
  echo "AGENT_UPDATE_DEFER_SECONDS=0" >> "`$ENV_FILE"
fi

if ! grep -q '^AGENT_UPDATE_JITTER_MAX_SECONDS=' "`$ENV_FILE"; then
  echo "AGENT_UPDATE_JITTER_MAX_SECONDS=60" >> "`$ENV_FILE"
fi

if ! grep -q '^AGENT_UPDATE_SELF_RESTART_DELAY_SECONDS=' "`$ENV_FILE"; then
  echo "AGENT_UPDATE_SELF_RESTART_DELAY_SECONDS=6" >> "`$ENV_FILE"
fi

set -a
. "`$ENV_FILE"
set +a

npm ci --workspaces --include=dev
npm -w shared run build
npm -w backend run db:migrate
npm -w backend run build

pm2 delete reap3r-backend 2>/dev/null || true
pm2 start "npm -w backend start" --name reap3r-backend --env production
pm2 save
echo "backend_ok"
"@

    $res = Invoke-SSHCommand $script
    if ($null -eq $res) { throw "Deploy-Backend failed" }
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

    $res = Invoke-SSHCommand $script
    if ($null -eq $res) { throw "Deploy-Frontend failed" }
    Write-Log "Frontend deployed" "Success"
}

Write-Log "=== MASSVISION Reap3r VPS deploy ===" "Info"
Write-Log "Server: ${VpsIP}:$VpsPort ($VpsUser)" "Info"

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
    Deploy-AgentBinaries
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
