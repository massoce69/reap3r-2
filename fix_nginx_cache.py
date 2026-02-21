import sys

with open('/etc/nginx/sites-enabled/massvision') as f:
    content = f.read()

old_block = """    location / {
        proxy_pass http://reap3r_frontend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }"""

new_block = """    location / {
        proxy_pass http://reap3r_frontend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
    }"""

count = content.count(old_block)
if count == 0:
    print("ERROR: block not found")
    sys.exit(1)

content = content.replace(old_block, new_block)
with open('/etc/nginx/sites-enabled/massvision', 'w') as f:
    f.write(content)
print(f"OK - replaced {count} blocks")
