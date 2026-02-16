@echo off
REM Déploiement MASSVISION Reap3r - VPS 72.62.181.194
REM Ce script exécute l'installation complète

setlocal enabledelayedexpansion

"C:\Program Files\Git\bin\bash.exe" -c "
set -e
echo '████████████████████████████████████████'
echo '  MASSVISION Reap3r - VPS DEPLOYMENT'
echo '████████████████████████████████████████'
echo ''

# Setup SSH key (one-time)
export SSH_KEY_PATH=~/.ssh/id_rsa

# Script de déploiement complet en base64

# Créer un deplpyment minimaliste
ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no root@72.62.181.194 'bash -s' <<'SCRIPT'
#!/bin/bash
set -e
echo '[*] Installation MASSVISION Reap3r...'
apt-get update && apt-get upgrade -y
apt-get install -y curl git make build-essential nodejs npm postgresql postgresql-contrib nginx certbot python3-certbot-nginx

npm install -g pm2
pm2 startup > /dev/null 2>&1

systemctl start postgresql
systemctl enable postgresql nginx
systemctl start nginx

APP_DIR=\"/app/massvision-reap3r\"
mkdir -p /app

if [ ! -d \"\$APP_DIR\" ]; then
  cd /app
  git clone https://github.com/massvision/reap3r.git massvision-reap3r || (echo 'Git clone failed' && mkdir -p massvision-reap3r)
else
  cd \"\$APP_DIR\"
  git pull origin main 2>/dev/null || true
fi

cd \"\$APP_DIR\"
npm ci --workspaces

mkdir -p backend frontend

cat > backend/.env <<'ENV'
NODE_ENV=production
DATABASE_URL=postgresql://reap3r:reap3r_secret@localhost:5432/reap3r
JWT_SECRET=$(openssl rand -base64 32)
HMAC_SECRET=$(openssl rand -base64 32)
LOG_LEVEL=info
BACKEND_PORT=4000
WEBSOCKET_PORT=4001
ENV

cat > frontend/.env.local <<'ENV'
NEXT_PUBLIC_API_URL=http://localhost:4000
ENV

export DATABASE_URL=\"postgresql://reap3r:reap3r_secret@localhost:5432/reap3r\"

sudo -u postgres psql -tc \"SELECT 1 FROM pg_user WHERE usename = 'reap3r'\" | grep -q 1 || \
  sudo -u postgres psql -c \"CREATE USER reap3r WITH PASSWORD 'reap3r_secret';\"

sudo -u postgres psql -tc \"SELECT 1 FROM pg_database WHERE datname = 'reap3r'\" | grep -q 1 || \
  sudo -u postgres psql -c \"CREATE DATABASE reap3r OWNER reap3r;\"

cd \"\$APP_DIR/backend\"
npm run db:migrate
npm run build

cd \"\$APP_DIR/frontend\"
npm run build

pm2 stop all 2>/dev/null || true
sleep 2

cd \"\$APP_DIR/backend\"
pm2 start \"npm start\" --name reap3r-backend --env production --time
pm2 start \"npm start\" --name reap3r-frontend --cwd \"\$APP_DIR/frontend\" --env production --time

pm2 save

cat > /etc/nginx/sites-available/reap3r <<'NGINX'
upstream backend { server localhost:4000; }
upstream frontend { server localhost:3000; }
server {
  listen 80 default_server;
  client_max_body_size 100M;
  location /api/ { proxy_pass http://backend; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection 'upgrade'; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; }
  location /ws { proxy_pass http://backend; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection 'upgrade'; }
  location / { proxy_pass http://frontend; proxy_http_version 1.1; proxy_set_header Host \$host; }
}
NGINX

ln -sf /etc/nginx/sites-available/reap3r /etc/nginx/sites-enabled/reap3r
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

echo '✓ Déploiement terminé!'
echo ''
sleep 2
pm2 list
echo ''
IP=\$(hostname -I | awk '{print \$1}')
echo \"Frontend: http://\$IP\"
echo \"API: http://\$IP/api/\"
SCRIPT
"

pause
