#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
# MASSVISION Reap3r — Ubuntu 24.04 LTS Installation Script
# ─────────────────────────────────────────────────────────
#
# Usage: sudo bash install_ubuntu_24_04.sh [--domain reap3r.example.com] [--email admin@example.com]
#
# Prerequisites: Fresh Ubuntu 24.04 LTS server with root access
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DOMAIN=""
EMAIL=""
INSTALL_DIR="/opt/massvision/reap3r"
DATA_DIR="/var/lib/massvision/reap3r"

log()  { echo -e "${GREEN}[REAP3R]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --domain) DOMAIN="$2"; shift 2 ;;
        --email)  EMAIL="$2";  shift 2 ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    read -rp "Enter server domain (e.g., reap3r.example.com): " DOMAIN
fi
if [[ -z "$EMAIL" ]]; then
    read -rp "Enter admin email (for Let's Encrypt): " EMAIL
fi

# ─── Check prerequisites ─────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo)"
    exit 1
fi

source /etc/os-release
if [[ "$VERSION_ID" != "24.04" ]]; then
    warn "This script is optimized for Ubuntu 24.04 LTS. Current: $VERSION_ID"
    read -rp "Continue anyway? [y/N] " -n 1 reply
    echo
    [[ "$reply" =~ ^[Yy]$ ]] || exit 1
fi

log "Starting MASSVISION Reap3r installation on Ubuntu 24.04 LTS"
log "Domain: $DOMAIN"
log "Email:  $EMAIL"

# ─── Step 1: System update ───────────────────────────────

log "Step 1/8: Updating system packages..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
apt-get install -y -qq \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    software-properties-common \
    ufw \
    fail2ban \
    unattended-upgrades \
    jq \
    htop \
    git

# ─── Step 2: Docker installation ─────────────────────────

log "Step 2/8: Installing Docker Engine..."
if ! command -v docker &>/dev/null; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    systemctl enable docker
    systemctl start docker
    log "Docker installed: $(docker --version)"
else
    log "Docker already installed: $(docker --version)"
fi

# ─── Step 3: Create service user ─────────────────────────

log "Step 3/8: Creating service user..."
if ! id -u massvision &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" -m massvision
    usermod -aG docker massvision
    log "Service user 'massvision' created"
else
    log "Service user 'massvision' already exists"
fi

# ─── Step 4: Directory structure ──────────────────────────

log "Step 4/8: Creating directory structure..."
mkdir -p "$INSTALL_DIR"/{infra/nginx,infra/prometheus,infra/grafana/provisioning,infra/certs,backups,logs}
mkdir -p "$DATA_DIR"/{postgres,prometheus,grafana}

# ─── Step 5: Firewall configuration ──────────────────────

log "Step 5/8: Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp    # HTTP (redirect to HTTPS)
ufw allow 443/tcp   # HTTPS
# Do NOT expose 4000, 5432, 9090, 3001 — only accessible via internal Docker network
ufw --force enable
log "Firewall configured: HTTP, HTTPS, SSH only"

# ─── Step 6: Fail2Ban configuration ──────────────────────

log "Step 6/8: Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.d/massvision.conf << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600
EOF

systemctl enable fail2ban
systemctl restart fail2ban
log "Fail2Ban configured"

# ─── Step 7: Generate secrets ────────────────────────────

log "Step 7/8: Generating secrets..."
ENV_FILE="$INSTALL_DIR/.env"

if [[ ! -f "$ENV_FILE" ]]; then
    JWT_SECRET=$(openssl rand -hex 32)
    HMAC_SECRET=$(openssl rand -hex 32)
    DB_PASSWORD=$(openssl rand -hex 24)
    GRAFANA_PASSWORD=$(openssl rand -base64 16)

    cat > "$ENV_FILE" << EOF
# ─── MASSVISION Reap3r Production Config ───
# Generated: $(date -Iseconds)
# Server: $DOMAIN

# Database
DB_NAME=reap3r
DB_USER=reap3r
DB_PASSWORD=$DB_PASSWORD

# Security
JWT_SECRET=$JWT_SECRET
HMAC_SECRET=$HMAC_SECRET

# URLs
CORS_ORIGIN=https://$DOMAIN
API_URL=https://$DOMAIN
WS_URL=wss://$DOMAIN
GRAFANA_URL=https://$DOMAIN/grafana

# TLS
TLS_CERT_PATH=$INSTALL_DIR/infra/certs/fullchain.pem
TLS_KEY_PATH=$INSTALL_DIR/infra/certs/privkey.pem

# Grafana
GRAFANA_USER=admin
GRAFANA_PASSWORD=$GRAFANA_PASSWORD
EOF

    chmod 600 "$ENV_FILE"
    chown massvision:massvision "$ENV_FILE"
    log "Secrets generated and saved to $ENV_FILE"
else
    warn ".env file already exists, skipping secret generation"
fi

# ─── Step 8: TLS with Let's Encrypt ──────────────────────

log "Step 8/8: Setting up TLS certificate..."
if ! command -v certbot &>/dev/null; then
    apt-get install -y -qq certbot
fi

# Generate self-signed cert for initial startup, then replace with Let's Encrypt
CERT_DIR="$INSTALL_DIR/infra/certs"
if [[ ! -f "$CERT_DIR/fullchain.pem" ]]; then
    log "Generating temporary self-signed certificate..."
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout "$CERT_DIR/privkey.pem" \
        -out "$CERT_DIR/fullchain.pem" \
        -subj "/C=US/ST=State/L=City/O=MASSVISION/CN=$DOMAIN"

    log "Self-signed cert created. Run this after DNS is configured:"
    echo -e "${CYAN}"
    echo "  certbot certonly --standalone -d $DOMAIN --email $EMAIL --agree-tos --no-eff-email"
    echo "  cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $CERT_DIR/fullchain.pem"
    echo "  cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $CERT_DIR/privkey.pem"
    echo "  docker compose -f docker-compose.prod.yml restart nginx"
    echo -e "${NC}"
fi

# ─── Create systemd service ──────────────────────────────

log "Creating systemd service..."
cat > /etc/systemd/system/massvision-reap3r.service << EOF
[Unit]
Description=MASSVISION Reap3r Platform
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=massvision
Group=massvision
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=/usr/bin/docker compose -f docker-compose.prod.yml up -d
ExecStop=/usr/bin/docker compose -f docker-compose.prod.yml down
ExecReload=/usr/bin/docker compose -f docker-compose.prod.yml restart

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable massvision-reap3r.service

# ─── Auto-renewal cron ───────────────────────────────────

cat > /etc/cron.d/massvision-certbot << EOF
0 3 * * * root certbot renew --quiet --deploy-hook "cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $CERT_DIR/fullchain.pem && cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $CERT_DIR/privkey.pem && docker compose -f $INSTALL_DIR/docker-compose.prod.yml restart nginx"
EOF

# ─── Unattended upgrades ─────────────────────────────────

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

# ─── Summary ─────────────────────────────────────────────

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  MASSVISION Reap3r — Installation Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Domain:         ${CYAN}$DOMAIN${NC}"
echo -e "  Install dir:    ${CYAN}$INSTALL_DIR${NC}"
echo -e "  Data dir:       ${CYAN}$DATA_DIR${NC}"
echo -e "  Env file:       ${CYAN}$ENV_FILE${NC}"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo -e "  1. Copy project files to $INSTALL_DIR"
echo -e "  2. cd $INSTALL_DIR"
echo -e "  3. docker compose -f docker-compose.prod.yml build"
echo -e "  4. docker compose -f docker-compose.prod.yml up -d"
echo -e "  5. Configure DNS A record: $DOMAIN → $(curl -s ifconfig.me || echo '<YOUR_IP>')"
echo -e "  6. Replace self-signed cert with Let's Encrypt (see above)"
echo ""
echo -e "  ${YELLOW}Default credentials:${NC}"
echo -e "  Admin:    admin@massvision.local / Admin123!@#"
echo -e "  Grafana:  admin / $(grep GRAFANA_PASSWORD "$ENV_FILE" | cut -d= -f2)"
echo ""
echo -e "  ${YELLOW}Management commands:${NC}"
echo -e "  sudo systemctl start massvision-reap3r"
echo -e "  sudo systemctl stop massvision-reap3r"
echo -e "  sudo systemctl restart massvision-reap3r"
echo -e "  sudo systemctl status massvision-reap3r"
echo ""
