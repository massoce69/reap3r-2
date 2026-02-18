#!/bin/bash
# Test job creation via API
set -e

TOKEN=$(curl -s -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@massvision.local","password":"Admin123!@#"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")

echo "Token: ${TOKEN:0:30}..."

if [ -z "$TOKEN" ]; then
  echo "Login failed. Trying other password..."
  TOKEN=$(curl -s -X POST http://localhost:4000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@massvision.pro","password":"changeme"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")
  echo "Token: ${TOKEN:0:30}..."
fi

echo ""
echo "--- Creating run_script job (whoami) ---"
RESULT=$(curl -s -X POST http://localhost:4000/api/jobs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"1bc83a24-10c1-4c64-a316-7a6958fdebb1","job_type":"run_script","payload":{"interpreter":"powershell","script":"whoami"},"reason":"Test from API"}')

echo "$RESULT" | python3 -m json.tool 2>/dev/null || echo "$RESULT"

JOB_ID=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
echo ""
echo "Job ID: $JOB_ID"
echo "Waiting 35s for heartbeat dispatch..."
sleep 35

echo ""
echo "--- Job status after 35s ---"
curl -s http://localhost:4000/api/jobs/$JOB_ID \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -m json.tool 2>/dev/null || echo "Failed to check job"
