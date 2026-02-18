#!/bin/bash
# Fix the /ws/ui nginx block and add upstream for UI WS on port 4002

CONFIG="/etc/nginx/sites-enabled/massvision"

# Check if reap3r_ui_ws upstream already exists
if ! grep -q 'reap3r_ui_ws' "$CONFIG"; then
    sed -i '/upstream reap3r_agent_ws {/i upstream reap3r_ui_ws {\n    server 127.0.0.1:4002;\n    keepalive 16;\n}\n' "$CONFIG"
    echo "Added reap3r_ui_ws upstream"
fi

# Use a temp file approach to avoid escaping hell
python3 << 'PYEOF'
import re

path = "/etc/nginx/sites-enabled/massvision"
with open(path) as f:
    content = f.read()

# Pattern for broken /ws/ui blocks (with missing variable values)
broken = re.compile(
    r'    location /ws/ui \{[^}]*\}',
    re.DOTALL
)

correct = """    location /ws/ui {
        proxy_pass http://reap3r_ui_ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }"""

content = broken.sub(correct, content)

with open(path, "w") as f:
    f.write(content)

print("Fixed /ws/ui blocks")
PYEOF

nginx -t && echo "Nginx config OK" || echo "Nginx config FAILED"
nginx -s reload && echo "Nginx reloaded" || echo "Nginx reload failed"
