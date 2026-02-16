# MASSVISION Reap3r - Automatic SSH Deployment
# This script manages SSH key authentication and triggers remote deployment

#!/bin/bash
set -e

VPS_IP="72.62.181.194"
VPS_USER="root"
SSH_KEY="$HOME/.ssh/id_ed25519"
PROJECT_DIR="$PWD"

echo "╔════════════════════════════════════════╗"
echo "║  Reap3r VPS Deployment - SSH Setup   ║"
echo "╚════════════════════════════════════════╝"

# Step 1: Ensure SSH key exists
if [ ! -f "$SSH_KEY" ]; then
    echo "⚠️  SSH key not found at $SSH_KEY"
    echo "Generating ED25519 key..."
    mkdir -p "$(dirname "$SSH_KEY")"
    ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -C "reap3r@$(hostname)"
    echo "✓ SSH key generated"
fi

# Step 2: Verify VPS accessibility via ssh-keyscan
echo "[1/4] Scanning VPS host key..."
ssh-keyscan -t ed25519 "$VPS_IP" >> ~/.ssh/known_hosts 2>/dev/null || true
echo "✓ Host key added to known_hosts"

# Step 3: Add public key to authorized_keys (Initial setup)
echo "[2/4] Attempting to add public key to VPS..."
PUB_KEY=$(cat "$SSH_KEY.pub")

# Create a small inline setup command
SETUP_SCRIPT=$(cat <<'EOF'
mkdir -p ~/.ssh && \
chmod 700 ~/.ssh && \
echo "$PUB_KEY" >> ~/.ssh/authorized_keys && \
chmod 600 ~/.ssh/authorized_keys && \
echo "SSH key configured successfully"
EOF
)

# For the first run, we'll provide instructions
echo ""
echo "⚠️ INITIAL SETUP REQUIRED"
echo "────────────────────────────────────────────"
echo "VPS SSH password auth is restricted. You need to:"
echo ""
echo "Option A: Add SSH key manually (RECOMMENDED)"
echo "─────────────────────────────────"
echo "1. Execute on VPS via your hosting provider console, or"
echo "2. Temporarily enable password auth in /etc/ssh/sshd_config"
echo "   - Set: PasswordAuthentication yes"
echo "   - Run: systemctl restart sshd"
echo ""
echo "3. Then add this public key:"
echo "────────────────────────────────────────"
cat "$SSH_KEY.pub"
echo "────────────────────────────────────────"
echo ""
echo "Option B: Push to GitHub and deploy from VPS"
echo "─────────────────────────────────"
echo "1. git push origin main"
echo "2. SSH to VPS (enable password temporarily)"
echo "3. curl -sSL https://raw.githubusercontent.com/YOU/massvision-reap3r/main/install-prod.sh | bash"
echo ""

# Try SSH connection (will fail if no key auth, that's expected)
echo "[3/4] Testing SSH connection..."
if ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new "$VPS_USER@$VPS_IP" exit 2>/dev/null; then
    echo "✓ SSH key authentication successful!"
    
    echo "[4/4] Deploying to VPS..."
    # Deploy the installation script
    cat "$PROJECT_DIR/install-prod.sh" | ssh -i "$SSH_KEY" "$VPS_USER@$VPS_IP" 'bash -s'
    echo ""
    echo "✓ Deployment complete!"
    echo "Access your apps:"
    echo "  Frontend: http://$VPS_IP"
    echo "  Backend:  http://$VPS_IP/api"
else
    echo "✗ SSH key authentication not ready yet"
    echo ""
    echo "📋 Next steps:"
    echo "1. On your VPS host: Add ~/.ssh/id_ed25519.pub to ~/.ssh/authorized_keys"
    echo "2. Or enable password authentication temporarily"
    echo "3. Then run this script again"
    echo ""
    exit 1
fi
