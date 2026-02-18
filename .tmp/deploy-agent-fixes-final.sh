#!/bin/bash
set -e

echo "=== Step 1: Git pull latest ==="
cd /app/massvision-reap3r
git pull origin main

echo ""
echo "=== Step 2: Install dependencies (including uuid fix) ==="
cd backend
npm install --legacy-peer-deps 2>&1 | tail -5

echo ""
echo "=== Step 3: Build backend ==="
npm run build 2>&1 | tail -5

echo ""
echo "=== Step 4: Seed test token ==="
export DATABASE_URL='postgresql://reap3r:reap3r_secret@localhost:5432/reap3r'
npm run seed:test-token

echo ""
echo "=== Step 5: Restart services ==="
cd /app/massvision-reap3r
pm2 restart reap3r-backend reap3r-frontend --update-env 2>&1 | tail -5
sleep 2

echo ""
echo "=== Step 6: Health checks ==="
curl -s http://localhost:4000/health 2>&1
echo ""
curl -s -o /dev/null -w "Frontend HTTP: %{http_code}\n" http://localhost:3000 2>&1

echo ""
echo "=== ✅ DEPLOY COMPLETE ==="
echo "Ready for agent testing"
