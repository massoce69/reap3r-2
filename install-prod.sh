#!/bin/bash
# MASSVISION Reap3r - One-Line Deployment
# Usage: bash <(curl -sSL <this-url>)

set -e

echo "████████████████████████████████████████"
echo "  MASSVISION Reap3r - VPS Deployment"
echo "████████████████████████████████████████"
echo ""

APP_DIR="/app/massvision-reap3r"

# 0. Swap Setup (Crucial for build)
echo "[0/8] Configuring Swap Memory..."
if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "Swap enabled"
else
    echo "Swap already exists"
fi

# 1. System Update
echo "[1/8] System Update..."
apt-get update > /dev/null 2>&1
apt-get upgrade -y > /dev/null 2>&1
apt-get autoremove -y > /dev/null 2>&1

# 2. Install Dependencies
echo "[2/8] Installing Dependencies..."
apt-get install -y \
    curl git wget ca-certificates \
    build-essential python3-dev \
    postgresql postgresql-contrib \
    nodejs npm \
    nginx certbot python3-certbot-nginx \
    > /dev/null 2>&1

# 3. PM2 Setup
echo "[3/8] PM2 Setup..."
npm install -g pm2 > /dev/null 2>&1
pm2 startup -u root > /dev/null 2>&1

# 4. PostgreSQL Setup
echo "[4/8] PostgreSQL Setup..."
systemctl enable postgresql > /dev/null 2>&1
systemctl start postgresql > /dev/null 2>&1

# Create user & DB
sudo -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = 'reap3r'" | grep -q 1 || \
  sudo -u postgres psql <<EOF > /dev/null 2>&1
CREATE USER reap3r WITH PASSWORD 'reap3r_secret';
ALTER USER reap3r CREATEDB;
EOF

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'reap3r'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE reap3r OWNER reap3r;" > /dev/null 2>&1

# 5. Clone & Setup Repository
echo "[5/8] Repository Clone..."
mkdir -p /app
cd /app

if [ ! -d "massvision-reap3r" ]; then
    # Try GitHub if provided, else create empty for manual
    if git ls-remote https://github.com/yourusername/massvision-reap3r.git >/dev/null 2>&1; then
        git clone https://github.com/yourusername/massvision-reap3r.git 2>/dev/null
    else
        mkdir -p massvision-reap3r
    fi
else
    # Only pull if .git exists (GitHub deployment)
    cd massvision-reap3r
    if [ -d ".git" ]; then
        git fetch origin 2>/dev/null && git reset --hard origin/main 2>/dev/null || true
    fi
    cd /app
fi

cd "$APP_DIR"

# 6. Dependencies & Build
echo "[6/8] Building Application (using swap)..."
echo "  Installing dependencies..."
# Use npm install instead of ci for flexibility and handle errors individually
if ! npm install --workspaces; then
    echo "  ⚠️ npm install failed! Retrying with --force..."
    npm install --workspaces --force
    if [ $? -ne 0 ]; then
        echo "  ❌ Failed to install dependencies."
        exit 1
    fi
fi

# Setup environment
mkdir -p backend frontend

cat > backend/.env <<EOF
NODE_ENV=production
DATABASE_URL=postgresql://reap3r:reap3r_secret@localhost:5432/reap3r
JWT_SECRET=$(openssl rand -base64 32)
HMAC_SECRET=$(openssl rand -base64 32)
LOG_LEVEL=info
BACKEND_PORT=4000
WEBSOCKET_PORT=4001
EOF

cat > frontend/.env.local <<EOF
NEXT_PUBLIC_API_URL=/api
EOF

# Build shared explicitly
echo "  Building shared library..."
cd "$APP_DIR/shared" || exit 1
npm run build || { echo "❌ Shared build failed"; exit 1; }

# Run migrations
export DATABASE_URL="postgresql://reap3r:reap3r_secret@localhost:5432/reap3r"
cd "$APP_DIR/backend"
echo "  Setting up backend..."
if ! npm run db:migrate; then
    echo "  ⚠️ Migration failed! Check DB logs."
    # Non-fatal for initial deploys sometimes, but usually fatal
    exit 1
fi
if ! npm run build; then
    echo "  ❌ Backend build failed."
    exit 1
fi

cd "$APP_DIR/frontend"
echo "  Building frontend (Next.js)..."
# Increase node memory limit
export NODE_OPTIONS="--max-old-space-size=4096"
if ! npm run build; then
    echo "  ❌ Frontend build failed."
    # Try cleaner build
    rm -rf .next node_modules
    npm install
    if ! npm run build; then
        echo "  ❌ Frontend build failed AGAIN."
        exit 1
    fi
fi

# 7. Services Start
echo "[7/8] Starting Services..."
pm2 stop all 2>/dev/null || true
sleep 2

cd "$APP_DIR/backend"
pm2 start "npm start" --name reap3r-backend --env production > /dev/null 2>&1

cd "$APP_DIR/frontend"
pm2 start "npm start" --name reap3r-frontend --env production > /dev/null 2>&1

pm2 save > /dev/null 2>&1

# 8. Nginx Configuration
echo "[8/8] Nginx Configuration..."
cat > /etc/nginx/sites-available/reap3r <<'NGINXCONF'
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
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
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

ln -sf /etc/nginx/sites-available/reap3r /etc/nginx/sites-enabled/reap3r
rm -f /etc/nginx/sites-enabled/default
nginx -t > /dev/null 2>&1
systemctl enable nginx > /dev/null 2>&1
systemctl restart nginx > /dev/null 2>&1

# Verification
sleep 3

echo ""
echo "████████████████████████████████████████"
echo "  ✓ DEPLOYMENT COMPLETE!"
echo "████████████████████████████████████████"
echo ""
echo "Status:"
pm2 list
echo ""
echo "Access:"
echo "  Frontend: http://$(hostname -I | awk '{print $1}')"
echo "  API: http://$(hostname -I | awk '{print $1}')/api/"
echo ""
echo "Commands:"
echo "  pm2 logs              - View logs"
echo "  pm2 status            - Service status"
echo "  pm2 restart all       - Restart services"
echo ""
