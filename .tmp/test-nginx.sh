#!/bin/bash
echo "=== Test via Nginx (as browser would) ==="
curl -s -X POST http://72.62.181.194/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@massvision.local","password":"Admin123!@#"}' 2>&1

echo ""
echo "=== Test Nginx frontend ==="
curl -s -o /dev/null -w "HTTP %{http_code}" http://72.62.181.194/ 2>&1
echo ""
