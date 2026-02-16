#!/bin/bash
# Script d'installation auto pour le VPS root@72.62.181.194

set -e

echo "████████████████████████████████████████"
echo "  MASSVISION Reap3r - AUTO DEPLOYMENT"
echo "████████████████████████████████████████"
echo ""

# ============================================
# 1. SYSTEM SETUP
# ============================================

echo "[1/10] Mise à jour du système..."
apt-get update > /dev/null 2>&1
apt-get upgrade -y > /dev/null 2>&1
apt-get install -y curl git wget build-essential > /dev/null 2>&1

# ============================================
# 2. INSTALL NODE.JS
# ============================================

echo "[2/10] Installation de Node.js..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash - > /dev/null 2>&1
apt-get install -y nodejs > /dev/null 2>&1
echo "Node.js: $(node -v)"

# ============================================
# 3. INSTALL PM2
# ============================================

echo "[3/10] Installation de PM2..."
npm install -g pm2 > /dev/null 2>&1
pm2 startup > /dev/null 2>&1

# ============================================
# 4. INSTALL POSTGRESQL
# ============================================

echo "[4/10] Installation de PostgreSQL..."
apt-get install -y postgresql postgresql-contrib > /dev/null 2>&1
systemctl enable postgresql > /dev/null 2>&1
systemctl start postgresql > /dev/null 2>&1

# ============================================
# 5. INSTALL NGINX
# ============================================

echo "[5/10] Installation de Nginx..."
apt-get install -y nginx certbot python3-certbot-nginx > /dev/null 2>&1
systemctl enable nginx > /dev/null 2>&1

# ============================================
# 6. CLONE REPOSITORY
# ============================================

echo "[6/10] Clonage du dépôt..."
APP_DIR="/app/massvision-reap3r"
mkdir -p /app

if [ ! -d "$APP_DIR" ]; then
    cd /app
    git clone https://github.com/yourusername/massvision-reap3r.git massvision-reap3r 2>/dev/null || mkdir -p massvision-reap3r
else
    cd "$APP_DIR"
    git pull origin main 2>/dev/null || true
fi

# ============================================
# 7. INSTALL DEPENDENCIES
# ============================================

echo "[7/10] Installation des dépendances..."
cd "$APP_DIR"
npm ci --workspaces > /dev/null 2>&1

# ============================================
# 8. SETUP ENVIRONMENT
# ============================================

echo "[8/10] Configuration de l'environnement..."

# Backend .env
cat > "$APP_DIR/backend/.env" <<EOF
NODE_ENV=production
DATABASE_URL=postgresql://reap3r:reap3r_secret@localhost:5432/reap3r
JWT_SECRET=$(openssl rand -base64 32)
HMAC_SECRET=$(openssl rand -base64 32)
LOG_LEVEL=info
BACKEND_PORT=4000
WEBSOCKET_PORT=4001
EOF

# Frontend .env.local
cat > "$APP_DIR/frontend/.env.local" <<EOF
NEXT_PUBLIC_API_URL=http://localhost:4000
EOF

# ============================================
# 9. SETUP DATABASE
# ============================================

echo "[9/10] Configuration de PostgreSQL..."

# Create user
sudo -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = 'reap3r'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER reap3r WITH PASSWORD 'reap3r_secret';" 2>/dev/null || true

# Create database
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'reap3r'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE reap3r OWNER reap3r;" 2>/dev/null || true

# Migrations
export DATABASE_URL="postgresql://reap3r:reap3r_secret@localhost:5432/reap3r"
cd "$APP_DIR/backend"
npm run db:migrate > /dev/null 2>&1

# Build
echo "[BUILD] Backend..."
npm run build > /dev/null 2>&1

echo "[BUILD] Frontend..."
cd "$APP_DIR/frontend"
npm run build > /dev/null 2>&1

# ============================================
# 10. START SERVICES
# ============================================

echo "[10/10] Démarrage des services..."

# Stop existing
pm2 stop reap3r-backend 2>/dev/null || true
pm2 stop reap3r-frontend 2>/dev/null || true
sleep 2

# Start backend
cd "$APP_DIR/backend"
export DATABASE_URL="postgresql://reap3r:reap3r_secret@localhost:5432/reap3r"
pm2 start "npm start" --name "reap3r-backend" --env production --time > /dev/null 2>&1

# Start frontend
cd "$APP_DIR/frontend"
pm2 start "npm start" --name "reap3r-frontend" --env production --time > /dev/null 2>&1

pm2 save > /dev/null 2>&1

# ============================================
# NGINX CONFIGURATION
# ============================================

cat > /etc/nginx/sites-available/reap3r-prod <<'NGINXCONF'
upstream backend {
    server localhost:4000;
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
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
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

# ============================================
# VERIFICATION
# ============================================

sleep 3

echo ""
echo "████████████████████████████████████████"
echo "  ✓ DÉPLOIEMENT TERMINÉ!"
echo "████████████████████████████████████████"
echo ""
echo "Services:"
pm2 list
echo ""
echo "Accédez à:"
echo "  🌐 Frontend: http://$(hostname -I | awk '{print $1}')"
echo "  📡 API: http://$(hostname -I | awk '{print $1}')/api/"
echo "  💬 WebSocket: ws://$(hostname -I | awk '{print $1}')/ws"
echo ""
echo "Commandes utiles:"
echo "  pm2 logs              - Voir les logs"
echo "  pm2 status            - État des services"
echo "  pm2 restart all       - Redémarrer"
echo ""
