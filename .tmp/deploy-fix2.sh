#!/bin/bash
set -e
echo "=== DEPLOY: Resetting local changes ==="
cd /app/massvision-reap3r
git stash --include-untracked 2>/dev/null || true
git checkout -- . 2>/dev/null || true
git clean -fd 2>/dev/null || true

echo "=== DEPLOY: Pulling latest code ==="
git pull origin main

echo "=== DEPLOY: Installing backend dependencies ==="
cd backend
npm install --legacy-peer-deps 2>&1 | tail -5

echo "=== DEPLOY: Running admin password reset ==="
export DATABASE_URL='postgresql://reap3r:reap3r_secret@localhost:5432/reap3r'
npx tsx src/scripts/reset-admin.ts

echo "=== DEPLOY: Building backend ==="
npm run build 2>&1 | tail -5

echo "=== DEPLOY: Restarting backend ==="
cd /app/massvision-reap3r
pm2 restart reap3r-backend --update-env 2>&1 | tail -5
sleep 2

echo "=== DEPLOY: Testing login ==="
curl -s -X POST http://localhost:4000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@massvision.local","password":"Admin123!@#"}' | head -200

echo ""
echo "=== DEPLOY: Health check ==="
curl -s http://localhost:4000/health | head -50

echo ""
echo "=== DEPLOY: DONE ==="
