#!/bin/bash
# MASSVISION Reap3r - VPS Auto Deploy
# Exécutez avec: C:\Program Files\Git\bin\bash.exe deploy-auto.sh

set -e

echo ""
echo "████████████████████████████████████████"
echo "  MASSVISION Reap3r - VPS AUTO DEPLOY"
echo "████████████████████████████████████████"
echo ""

VPS_IP="72.62.181.194"
VPS_USER="root"
VPS_PASS="Chenhao\$macross69"

echo "[*] Déploiement sur $VPS_IP..."
echo ""

# Script complet
DEPLOY_SCRIPT='#!/bin/bash
set -e
echo "[1/6] Système..."
apt-get update > /dev/null && apt-get upgrade -y > /dev/null
apt-get install -y curl git nodejs npm postgresql nginx > /dev/null

echo "[2/6] PM2 & Services..."
npm install -g pm2 > /dev/null && pm2 startup > /dev/null
systemctl enable postgresql nginx > /dev/null && systemctl start postgresql nginx > /dev/null

echo "[3/6] Dépôt..."
mkdir -p /app && cd /app
[ -d massvision-reap3r ] || git clone https://github.com/massvision/reap3r.git massvision-reap3r 2>/dev/null || mkdir -p massvision-reap3r
cd /app/massvision-reap3r
npm ci --workspaces > /dev/null

echo "[4/6] Config..."
mkdir -p backend frontend
cat > backend/.env <<EOF
NODE_ENV=production
DATABASE_URL=postgresql://reap3r:reap3r_secret@localhost:5432/reap3r
JWT_SECRET=$(openssl rand -base64 32)
HMAC_SECRET=$(openssl rand -base64 32)
LOG_LEVEL=info
EOF
cat > frontend/.env.local <<EOF
NEXT_PUBLIC_API_URL=http://localhost:4000
EOF

export DATABASE_URL="postgresql://reap3r:reap3r_secret@localhost:5432/reap3r"
sudo -u postgres createuser -D -l reap3r 2>/dev/null || true
sudo -u postgres createdb -O reap3r reap3r 2>/dev/null || true

echo "[5/6] Build..."
cd backend && npm run db:migrate > /dev/null && npm run build > /dev/null
cd ../frontend && npm run build > /dev/null

echo "[6/6] Services..."
pm2 stop all 2>/dev/null | true
sleep 2
cd ../backend && pm2 start "npm start" --name reap3r-backend --env production > /dev/null
cd ../frontend && pm2 start "npm start" --name reap3r-frontend --env production > /dev/null
pm2 save > /dev/null

echo ""
echo "████████████████████████████████████████"
echo "  ✓ DÉPLOIEMENT TERMINÉ!"
echo "████████████████████████████████████████"
pm2 list
'

# Envoyer et exécuter
echo "Exécution du déploiement..."
echo ""

ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PasswordAuthentication=yes \
    -o PubkeyAuthentication=no \
    root@$VPS_IP "bash -s" <<< "$DEPLOY_SCRIPT"

echo ""
echo "Frontend: http://$VPS_IP"
echo "API: http://$VPS_IP/api/"
echo ""
