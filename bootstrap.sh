#!/bin/bash
# MASSVISION Reap3r - Bootstrap Deployment Script
# Usage: curl -fsSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/bootstrap.sh | bash
# OR: bash <(curl -fsSL https://your-vps-url/bootstrap.sh)

set -e

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

APP_DIR="/app/massvision-reap3r"
REPO_URL="${REPO_URL:-https://github.com/yourusername/massvision-reap3r.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
NODE_VERSION="20"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ─────────────────────────────────────────────
# Functions
# ─────────────────────────────────────────────

log_info() { echo -e "${BLUE}ℹ${NC} $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Ce script doit être exécuté en tant que root"
    fi
}

# ─────────────────────────────────────────────
# System Setup
# ─────────────────────────────────────────────

log_info "=== MASSVISION Reap3r Bootstrap ==="
log_info "Serveur préparation..."

check_root

# Update system
log_info "Mise à jour des packages système..."
apt-get update > /dev/null 2>&1
apt-get upgrade -y > /dev/null 2>&1

# Install curl if missing
if ! command -v curl &> /dev/null; then
    apt-get install -y curl > /dev/null 2>&1
fi

# Install Node.js
if ! command -v node &> /dev/null; then
    log_info "Installation de Node.js $NODE_VERSION..."
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -
    apt-get install -y nodejs > /dev/null 2>&1
else
    log_success "Node.js déjà installé: $(node -v)"
fi

# Install PM2
if ! command -v pm2 &> /dev/null; then
    log_info "Installation de PM2..."
    npm install -g pm2 > /dev/null 2>&1
    pm2 startup > /dev/null 2>&1
else
    log_success "PM2 déjà installé"
fi

# Install PostgreSQL
if ! command -v psql &> /dev/null; then
    log_info "Installation de PostgreSQL..."
    apt-get install -y postgresql postgresql-contrib > /dev/null 2>&1
    systemctl enable postgresql > /dev/null 2>&1
    systemctl start postgresql > /dev/null 2>&1
else
    log_success "PostgreSQL déjà installé"
fi

# Install Nginx
if ! command -v nginx &> /dev/null; then
    log_info "Installation de Nginx..."
    apt-get install -y nginx certbot python3-certbot-nginx > /dev/null 2>&1
    systemctl enable nginx > /dev/null 2>&1
else
    log_success "Nginx déjà installé"
fi

# Install Git
if ! command -v git &> /dev/null; then
    log_info "Installation de Git..."
    apt-get install -y git > /dev/null 2>&1
else
    log_success "Git déjà installé"
fi

log_success "Dépendances système installées"

# ─────────────────────────────────────────────
# Repository
# ─────────────────────────────────────────────

log_info "Configuration du dépôt..."

if [ ! -d "$APP_DIR" ]; then
    mkdir -p /app
    cd /app
    log_info "Clonage du dépôt..."
    git clone -b $REPO_BRANCH $REPO_URL massvision-reap3r
else
    cd "$APP_DIR"
    log_info "Mise à jour du dépôt..."
    git fetch origin
    git reset --hard origin/$REPO_BRANCH
fi

cd "$APP_DIR"
log_success "Dépôt préparé"

# ─────────────────────────────────────────────
# Dependencies
# ─────────────────────────────────────────────

log_info "Installation des dépendances npm..."
npm ci --workspaces > /dev/null 2>&1

log_success "Dépendances npm installées"

# ─────────────────────────────────────────────
# Environment
# ─────────────────────────────────────────────

log_info "Configuration de l'environnement..."

# Backend .env
if [ ! -f "$APP_DIR/backend/.env" ]; then
    log_info "Création de backend/.env..."
    cat > "$APP_DIR/backend/.env" <<EOF
NODE_ENV=production
DATABASE_URL=postgresql://reap3r:reap3r_secret@localhost:5432/reap3r
JWT_SECRET=$(openssl rand -base64 32)
HMAC_SECRET=$(openssl rand -base64 32)
LOG_LEVEL=info
BACKEND_PORT=4000
WEBSOCKET_PORT=4001
EOF
else
    log_warn "backend/.env existe déjà"
fi

# Frontend .env.local
if [ ! -f "$APP_DIR/frontend/.env.local" ]; then
    log_info "Création de frontend/.env.local..."
    cat > "$APP_DIR/frontend/.env.local" <<EOF
# Leave empty to default to same-origin (Nginx proxies /api/* in production).
NEXT_PUBLIC_API_URL=
EOF
else
    log_warn "frontend/.env.local existe déjà"
fi

log_success "Environnement configuré"

# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────

log_info "Configuration de PostgreSQL..."

# Create user
sudo -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = 'reap3r'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER reap3r WITH PASSWORD 'reap3r_secret';" > /dev/null 2>&1

# Create database
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'reap3r'" | grep -q 1 || \
    sudo -u postgres psql <<EOF > /dev/null 2>&1
CREATE DATABASE reap3r OWNER reap3r;
GRANT CONNECT ON DATABASE reap3r TO reap3r;
GRANT USAGE ON SCHEMA public TO reap3r;
GRANT CREATE ON SCHEMA public TO reap3r;
EOF

log_success "PostgreSQL configuré"

# ─────────────────────────────────────────────
# Migrations & Build
# ─────────────────────────────────────────────

log_info "Exécution des migrations..."
export DATABASE_URL="postgresql://reap3r:reap3r_secret@localhost:5432/reap3r"
cd "$APP_DIR/backend"
npm run db:migrate > /dev/null 2>&1
log_success "Migrations appliquées"

log_info "Build du backend..."
npm run build > /dev/null 2>&1
log_success "Backend construit"

log_info "Build du frontend..."
cd "$APP_DIR/frontend"
npm run build > /dev/null 2>&1
log_success "Frontend construit"

# ─────────────────────────────────────────────
# Services
# ─────────────────────────────────────────────

log_info "Démarrage des services..."

# Stop existing
pm2 stop reap3r-backend 2>/dev/null || true
pm2 stop reap3r-frontend 2>/dev/null || true
sleep 2

# Start backend
cd "$APP_DIR/backend"
export DATABASE_URL="postgresql://reap3r:reap3r_secret@localhost:5432/reap3r"
pm2 start "npm start" \
    --name "reap3r-backend" \
    --env production \
    --interpretation "shell" > /dev/null 2>&1

# Start frontend
cd "$APP_DIR/frontend"
pm2 start "npm start" \
    --name "reap3r-frontend" \
    --interpretation "shell" > /dev/null 2>&1

pm2 save > /dev/null 2>&1

sleep 3
log_success "Services démarrés"

# ─────────────────────────────────────────────
# Nginx
# ─────────────────────────────────────────────

log_info "Configuration de Nginx..."

cat > /etc/nginx/sites-available/reap3r-prod <<'NGINXCONF'
upstream backend_http {
    server 127.0.0.1:4000;
}

upstream backend_ws_agent {
    server 127.0.0.1:4001;
}

upstream frontend {
    server localhost:3000;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    client_max_body_size 100M;

    location /api/ {
        proxy_pass http://backend_http;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws/agent {
        proxy_pass http://backend_ws_agent;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://backend_http;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://frontend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINXCONF

ln -sf /etc/nginx/sites-available/reap3r-prod /etc/nginx/sites-enabled/reap3r-prod
rm -f /etc/nginx/sites-enabled/default

nginx -t > /dev/null 2>&1
systemctl restart nginx

log_success "Nginx configuré"

# ─────────────────────────────────────────────
# Verification
# ─────────────────────────────────────────────

log_info "Vérification..."
sleep 2

if curl -s http://localhost:4000/health &> /dev/null; then
    log_success "Backend actif"
else
    log_warn "Backend peut ne pas être actif"
fi

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────

echo ""
log_success "======================================"
log_success "✓ Déploiement terminé!"
log_success "======================================"
echo ""
echo "Accédez à votre application:"
echo "  Frontend: http://$(hostname -I | awk '{print $1}')"
echo "  API: http://$(hostname -I | awk '{print $1}')/api/"
echo ""
echo "Gestion des services:"
echo "  pm2 status"
echo "  pm2 logs"
echo "  pm2 restart all"
echo ""
echo "Logs en temps réel:"
echo "  pm2 logs reap3r-backend"
echo "  pm2 logs reap3r-frontend"
echo ""
