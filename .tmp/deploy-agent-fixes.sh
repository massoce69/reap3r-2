#!/bin/bash
set -e

echo "=== DEPLOY PHASE 1: Git pull + dependencies ==="
cd /app/massvision-reap3r
git pull origin main
cd backend
npm install --legacy-peer-deps 2>&1 | tail -3

echo ""
echo "=== DEPLOY PHASE 2: Build backend ==="
npm run build 2>&1 | tail -5

echo ""
echo "=== DEPLOY PHASE 3: DB migrations ==="
export DATABASE_URL='postgresql://reap3r:reap3r_secret@localhost:5432/reap3r'
npm run db:migrate 2>&1 | tail -5

echo ""
echo "=== DEPLOY PHASE 4: Seed test enrollment token ==="
npm run seed:test-token 2>&1

echo ""
echo "=== DEPLOY PHASE 5: Restart backend + frontend ==="
cd /app/massvision-reap3r
pm2 restart reap3r-backend reap3r-frontend --update-env 2>&1 | tail -5
sleep 3

echo ""
echo "=== DEPLOY PHASE 6: Health check ==="
curl -s http://localhost:4000/health 2>&1 | head -50

echo ""
echo "=== DEPLOY COMPLETE ==="
echo "Backend API:  http://72.62.181.194:4000"
echo "Frontend:     http://72.62.181.194"
echo "Agent WS:     ws://72.62.181.194/ws/agent (via Nginx proxy)"
