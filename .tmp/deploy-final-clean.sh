#!/bin/bash
set -e

echo "=== Step 1: Git pull latest (with stash) ==="
cd /app/massvision-reap3r
git stash --include-untracked
git pull origin main

echo ""
echo "=== Step 2: Install dependencies ==="
cd backend
npm install --legacy-peer-deps 2>&1 | grep -E "added|audited"

echo ""
echo "=== Step 3: Build backend ==="
npm run build 2>&1 | tail -3

echo ""
echo "=== Step 4: Seed test token ==="
export DATABASE_URL='postgresql://reap3r:reap3r_secret@localhost:5432/reap3r'
npm run seed:test-token 2>&1

echo ""
echo "=== Step 5: Restart services ==="
cd /app/massvision-reap3r
pm2 restart reap3r-backend reap3r-frontend --update-env 2>&1 | grep -E "online|stopped"
sleep 2

echo ""
echo "=== Step 6: Health check ==="
curl -s http://localhost:4000/health

echo ""
echo "=== ✅ DEPLOY COMPLETE ==="
