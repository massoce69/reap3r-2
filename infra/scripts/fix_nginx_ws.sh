#!/bin/bash
set -euo pipefail

# Fix WS proxy config to match unified gateway on backend :4000.
CONFIG="${1:-/etc/nginx/sites-enabled/massvision}"
BACKUP="${CONFIG}.bak.$(date +%Y%m%d%H%M%S)"

if [ ! -f "$CONFIG" ]; then
  echo "Config not found: $CONFIG"
  exit 1
fi

cp "$CONFIG" "$BACKUP"

# Legacy dedicated WS upstreams -> unified backend.
sed -i 's/server 127\.0\.0\.1:4001;/server 127.0.0.1:4000;/g' "$CONFIG"
sed -i 's/server 127\.0\.0\.1:4002;/server 127.0.0.1:4000;/g' "$CONFIG"

# Route both WS locations to backend upstream when legacy upstream names are present.
sed -i 's/proxy_pass http:\/\/reap3r_agent_ws;/proxy_pass http:\/\/reap3r_backend;/g' "$CONFIG"
sed -i 's/proxy_pass http:\/\/reap3r_ui_ws;/proxy_pass http:\/\/reap3r_backend;/g' "$CONFIG"

nginx -t
nginx -s reload
echo "WS proxy unified on :4000. Backup: $BACKUP"
