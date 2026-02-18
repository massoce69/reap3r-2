#!/bin/bash
# Test Remote Desktop end-to-end

AGENT_ID="1bc83a24-10c1-4c64-a316-7a6958fdebb1"
API="http://127.0.0.1:4000/api"

# Login
TOKEN=$(curl -s -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@massvision.local","password":"Admin123!@#"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('token','FAIL'))")

echo "Token: ${TOKEN:0:30}..."

if [ "$TOKEN" = "FAIL" ] || [ -z "$TOKEN" ]; then
  echo "Login failed!"
  exit 1
fi

# Create remote_desktop_start job
echo "Creating remote_desktop_start job..."
RESULT=$(curl -s -X POST "$API/jobs" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"'"$AGENT_ID"'","job_type":"remote_desktop_start","payload":{"mode":"view","fps":2,"quality":50,"codec":"jpeg","scale":0.5},"reason":"RD test"}')

echo "Job result: $RESULT"

# Wait a bit for the job to be dispatched and frames to start
echo "Waiting 8 seconds for frames..."
sleep 8

# Check backend logs for frame relay
echo ""
echo "=== Backend logs (last 20 lines) ==="
pm2 logs reap3r-backend --lines 20 --nostream 2>&1 | tail -25
