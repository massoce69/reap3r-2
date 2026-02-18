#!/bin/bash
API="http://127.0.0.1:4000/api"
TOKEN=$(curl -s -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@massvision.local","password":"Admin123!@#"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('token','FAIL'))")
echo "Stopping RD stream..."
curl -s -X POST "$API/jobs" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"1bc83a24-10c1-4c64-a316-7a6958fdebb1","job_type":"remote_desktop_stop","payload":{},"reason":"stop"}'
echo ""
