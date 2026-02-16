#!/bin/bash
# ─────────────────────────────────────────────
# MASSVISION Reap3r — Deployment Script
# ─────────────────────────────────────────────

set -e

echo "🚀 MASSVISION Reap3r Deployment"
echo "================================"

# Configuration
APP_DIR="/app/massvision-reap3r"
NODE_VERSION="20"
DOMAIN="${DOMAIN:-api.massvision.local}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:3000}"
BACKEND_URL="${BACKEND_URL:-http://localhost:4000}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

# 1. Update system
log_info "Updating system packages..."
apt-get update
apt-get upgrade -y

# 2. Install Node.js if not present
if ! command -v node &> /dev/null; then
    log_info "Installing Node.js $NODE_VERSION..."
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | sudo -E bash -
    apt-get install -y nodejs
else
    log_info "Node.js already installed: $(node -v)"
fi

# 3. Install PM2 globally (process manager)
if ! command -v pm2 &> /dev/null; then
    log_info "Installing PM2..."
    npm install -g pm2
    pm2 startup
else
    log_info "PM2 already installed"
fi

# 4. Install PostgreSQL if not present
if ! command -v psql &> /dev/null; then
    log_info "Installing PostgreSQL..."
    apt-get install -y postgresql postgresql-contrib
    systemctl enable postgresql
    systemctl start postgresql
else
    log_info "PostgreSQL already installed"
fi

# 5. Clone or pull repository
if [ ! -d "$APP_DIR" ]; then
    log_info "Cloning repository..."
    mkdir -p /app
    cd /app
    git clone https://github.com/massvision/reap3r.git massvision-reap3r
else
    log_info "Pulling latest changes..."
    cd "$APP_DIR"
    git pull origin main
fi

cd "$APP_DIR"

# 6. Install dependencies
log_info "Installing dependencies..."
npm ci --workspaces
npm ci

# 7. Setup environment variables
if [ ! -f "$APP_DIR/backend/.env" ]; then
    log_info "Creating backend .env..."
    cat > "$APP_DIR/backend/.env" <<EOF
NODE_ENV=production
DATABASE_URL=postgresql://reap3r:reap3r_secret@localhost:5432/reap3r
JWT_SECRET=$(openssl rand -base64 32)
HMAC_SECRET=$(openssl rand -base64 32)
LOG_LEVEL=info
BACKEND_PORT=4000
WEBSOCKET_PORT=4001
EOF
fi

if [ ! -f "$APP_DIR/frontend/.env.local" ]; then
    log_info "Creating frontend .env.local..."
    cat > "$APP_DIR/frontend/.env.local" <<EOF
NEXT_PUBLIC_API_URL=$BACKEND_URL
EOF
fi

# 8. Create PostgreSQL user and database if needed
log_info "Setting up PostgreSQL..."
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'reap3r'" | grep -q 1 || \
    sudo -u postgres psql <<EOF
CREATE USER reap3r WITH PASSWORD 'reap3r_secret';
CREATE DATABASE reap3r OWNER reap3r;
GRANT ALL PRIVILEGES ON DATABASE reap3r TO reap3r;
EOF

# 9. Run database migrations
export DATABASE_URL="postgresql://reap3r:reap3r_secret@localhost:5432/reap3r"
log_info "Running database migrations..."
cd "$APP_DIR/backend"
npm run db:migrate

# 10. Build backend
log_info "Building backend..."
cd "$APP_DIR/backend"
npm run build

# 11. Build frontend
log_info "Building frontend..."
cd "$APP_DIR/frontend"
npm run build

# 12. Stop existing PM2 processes
log_info "Stopping existing processes..."
pm2 stop reap3r-backend 2>/dev/null || true
pm2 stop reap3r-frontend 2>/dev/null || true

# 13. Start backend with PM2
log_info "Starting backend..."
cd "$APP_DIR/backend"
pm2 start "npm run start" --name "reap3r-backend" --env production

# 14. Start frontend with PM2
log_info "Starting frontend..."
cd "$APP_DIR/frontend"
pm2 start "npm run start" --name "reap3r-frontend" --env production

# 15. Save PM2 startup
log_info "Saving PM2 startup configuration..."
pm2 save

# 16. Setup Nginx reverse proxy
if ! command -v nginx &> /dev/null; then
    log_info "Installing Nginx..."
    apt-get install -y nginx certbot python3-certbot-nginx
fi

log_info "Configuring Nginx..."
cat > /etc/nginx/sites-available/reap3r <<'NGINX'
upstream backend {
    server localhost:4000;
}

upstream frontend {
    server localhost:3000;
}

server {
    listen 80;
    server_name _;
    client_max_body_size 100M;

    # Backend API
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

    # WebSocket
    location /ws {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Frontend
    location / {
        proxy_pass http://frontend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/reap3r /etc/nginx/sites-enabled/reap3r
rm -f /etc/nginx/sites-enabled/default

nginx -t
systemctl restart nginx
systemctl enable nginx

# 17. Setup SSL with Let's Encrypt (optional)
log_warn "SSL setup: Run 'certbot --nginx' to configure SSL"

# 18. Verify services
log_info "Verifying services..."
sleep 2

HTTP_HEALTH=$(curl -s http://localhost:4000/health || echo "FAIL")
if [[ "$HTTP_HEALTH" == *"ok"* ]]; then
    log_info "Backend health check: PASS"
else
    log_warn "Backend health check: FAILED - $HTTP_HEALTH"
fi

# Display status
echo -e "\n${GREEN}================================${NC}"
echo -e "${GREEN}✓ Deployment Complete!${NC}"
echo -e "${GREEN}================================${NC}"
pm2 status
echo -e "\n${GREEN}URLs:${NC}"
echo "  Frontend: http://localhost (via Nginx)"
echo "  Backend:  http://localhost/api/"
echo "  WebSocket: ws://localhost/ws"
echo -e "\n${GREEN}PM2 Commands:${NC}"
echo "  pm2 logs          - View logs"
echo "  pm2 status        - Check status"
echo "  pm2 restart all   - Restart services"
echo "  pm2 stop all      - Stop services"
