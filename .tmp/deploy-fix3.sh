#!/bin/bash
set -e

echo "=== FIX 1: Reset PostgreSQL password for reap3r user ==="
sudo -u postgres psql -c "ALTER USER reap3r WITH PASSWORD 'reap3r_secret';" 2>&1

echo "=== FIX 2: Verify DB connection ==="
PGPASSWORD=reap3r_secret psql -h localhost -U reap3r -d reap3r -c "SELECT 1 AS connected;" 2>&1

echo "=== FIX 3: Run admin password reset ==="
cd /app/massvision-reap3r/backend
export DATABASE_URL='postgresql://reap3r:reap3r_secret@localhost:5432/reap3r'
npx tsx src/scripts/reset-admin.ts 2>&1

echo "=== FIX 4: Build backend ==="
npm run build 2>&1 | tail -5

echo "=== FIX 5: Restart PM2 ==="
cd /app/massvision-reap3r
pm2 restart reap3r-backend --update-env 2>&1 | tail -5
sleep 3

echo "=== FIX 6: Test login ==="
curl -s -X POST http://localhost:4000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@massvision.local","password":"Admin123!@#"}' 2>&1

echo ""
echo "=== FIX 7: Health check ==="
curl -s http://localhost:4000/health 2>&1

echo ""
echo "=== ALL DONE ==="
