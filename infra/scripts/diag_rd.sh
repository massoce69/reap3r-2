#!/bin/bash
API="http://127.0.0.1:4000/api"
AGENT="1bc83a24-10c1-4c64-a316-7a6958fdebb1"
TOKEN=$(curl -s -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@massvision.local","password":"Admin123!@#"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "=== Agent status & capabilities ==="
curl -s "$API/agents/$AGENT" -H "Authorization: Bearer $TOKEN" \
  | python3 -c "
import sys,json
a=json.load(sys.stdin)
print('status:', a.get('status'))
print('capabilities:', json.dumps(a.get('capabilities'), indent=2))
"

echo ""
echo "=== Current UI WS clients ==="
# Check recent WS connect/disconnect events
pm2 logs reap3r-backend --lines 200 --nostream 2>&1 | grep -i 'UI WS client' | tail -10

echo ""
echo "=== Nginx error log (last WS errors) ==="
tail -20 /var/log/nginx/error.log 2>/dev/null | grep -i 'ws\|websocket\|upgrade\|upstream' | tail -5

echo ""
echo "=== Nginx access log (ws/ui requests) ==="
tail -100 /var/log/nginx/access.log 2>/dev/null | grep 'ws/ui' | tail -5

echo ""  
echo "=== External WS test ==="
# Quick test: connect to WS via curl upgrade
curl -s -o /dev/null -w "%{http_code}" \
  --include \
  --no-buffer \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "http://127.0.0.1:4002/ws/ui?token=$TOKEN" \
  --max-time 2 2>&1 || true
echo ""
