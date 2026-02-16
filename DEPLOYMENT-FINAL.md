╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║               MASSVISION Reap3r - VPS Deployment Guide                    ║
║                         Production Deployment v1.0                         ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝


🎯 DEPLOYMENT STATUS
════════════════════════════════════════════════════════════════════════════

Target VPS:        72.62.181.194 (root)
Application:       Next.js + Fastify + PostgreSQL
Installation Dir:  /app/massvision-reap3r
Services:
  • Frontend (Next.js):      Port 3000 → Nginx Port 80
  • Backend (Fastify REST):  Port 4000
  • Backend (WebSocket):     Port 4001
  • Database (PostgreSQL):   Port 5432
  • Process Manager (PM2):   Auto-restart with systemd


🔒 SSH AUTHENTICATION SETUP (CRITICAL)
════════════════════════════════════════════════════════════════════════════

Current Issue:
  VPS has SSH key-based authentication enabled (password auth disabled)
  Your Windows machine has ED25519 SSH key at: %USERPROFILE%\.ssh\id_ed25519

Solution - Choose ONE of 3 options:

┌──────────────────────────────────────────────────────────────────────────┐
│ OPTION 1: Add SSH Public Key to VPS (RECOMMENDED - Most Secure)         │
│ ────────────────────────────────────────────────────────────────────────│
│                                                                          │
│ Your SSH Public Key:                                                    │
│ ────────────────────────────────────────────────────────────────────────│

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFLFggY/r3zEBFz3Q98dBB/3m2bR0b+aD73aHqRoLicz massi.oukkal@gmail.com

│ ────────────────────────────────────────────────────────────────────────│
│ On your VPS (via hosting provider console or control panel):            │
│                                                                          │
│ 1. Connect to VPS console/terminal                                      │
│ 2. Execute:                                                              │
│                                                                          │
│    mkdir -p ~/.ssh                                                       │
│    cat >> ~/.ssh/authorized_keys << 'EOF'                              │
│    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFLFggY/r3zEBFz3Q98dBB/3m2bR0b+aD73aHqRoLicz massi.oukkal@gmail.com
│    EOF                                                                   │
│    chmod 600 ~/.ssh/authorized_keys                                     │
│    chmod 700 ~/.ssh                                                      │
│                                                                          │
│ 3. Then from your Windows machine, run:                                │
│                                                                          │
│    PowerShell: cd C:\Projects\massvision-reap3r                        │
│    PowerShell: '& "C:\Program Files\Git\bin\bash.exe" deploy-ssh-setup.sh'
│                                                                          │
│ ✓ This option is fully automated after key setup                        │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│ OPTION 2: Temporarily Enable Password Authentication (QUICK)            │
│ ────────────────────────────────────────────────────────────────────────│
│                                                                          │
│ 1. Access VPS console/control panel (hosting provider)                 │
│ 2. Edit SSH configuration:                                              │
│                                                                          │
│    sudo nano /etc/ssh/sshd_config                                       │
│                                                                          │
│ 3. Change:                                                               │
│                                                                          │
│    PasswordAuthentication yes                                            │
│                                                                          │
│ 4. Restart SSH:                                                          │
│                                                                          │
│    sudo systemctl restart sshd                                          │
│                                                                          │
│ 5. From Windows PowerShell:                                            │
│                                                                          │
│    cd C:\Projects\massvision-reap3r                                    │
│    powershell -ExecutionPolicy Bypass -File deploy-windows.ps1 -VpsPassword "Chenhao$macross69"
│                                                                          │
│ ⚠️  Security: Remember to disable password auth after deployment!       │
│    (Set PasswordAuthentication no when deployment completes)             │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│ OPTION 3: Git-based Deployment (Using GitHub/GitLab)                   │
│ ────────────────────────────────────────────────────────────────────────│
│                                                                          │
│ 1. Create private GitHub/GitLab repository                              │
│ 2. Push this code:                                                       │
│                                                                          │
│    cd C:\Projects\massvision-reap3r                                    │
│    git remote set-url origin https://github.com/yourusername/massvision-reap3r.git
│    git push -u origin main                                              │
│                                                                          │
│ 3. Access VPS console and run:                                         │
│                                                                          │
│    bash <(curl -sSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/install-prod.sh)
│                                                                          │
│ ✓ No SSH key setup needed - just a GitHub token (stored in PAT)         │
└──────────────────────────────────────────────────────────────────────────┘


📋 DEPLOYMENT SCRIPTS AVAILABLE
════════════════════════════════════════════════════════════════════════════

Script                     Purpose                                    Usage
─────────────────────────────────────────────────────────────────────────
install-prod.sh           Main installation script (automatic)
  → Installs all dependencies
  → Sets up PostgreSQL database
  → Configures Node.js + PM2
  → Installs and configures Nginx
  → Starts all services

deploy-ssh-setup.sh       SSH key management + auto-deploy             Bash
  → Verifies SSH keys
  → Adds host key to known_hosts
  → Provides instructions for key setup
  → Triggers remote deployment

deploy-windows.ps1        Windows PowerShell wrapper                   PowerShell
  → Checks for SSH keys
  → Prompts for VPS credentials if needed
  → Provides deployment options

Available from command line:
  PowerShell: powershell -ExecutionPolicy Bypass -File deploy-windows.ps1
  Git Bash:   bash deploy-ssh-setup.sh


🚀 QUICK START (RECOMMENDED PATH)
════════════════════════════════════════════════════════════════════════════

Step 1: Set Up SSH Key Access
─────────────────────────────────────────────────────────────────────────

On VPS (via console):
  
  mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys << 'EOF'
  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFLFggY/r3zEBFz3Q98dBB/3m2bR0b+aD73aHqRoLicz massi.oukkal@gmail.com
  EOF
  chmod 600 ~/.ssh/authorized_keys

Step 2: Deploy from Windows
─────────────────────────────────────────────────────────────────────────

PowerShell as Administrator:

  cd C:\Projects\massvision-reap3r
  & "C:\Program Files\Git\bin\bash.exe" deploy-ssh-setup.sh

Step 3: Verify Deployment
─────────────────────────────────────────────────────────────────────────

Wait 5-10 minutes for installation, then check:

  • Frontend:  http://72.62.181.194 (should show login page)
  • Backend:   http://72.62.181.194/api/health (check API status)
  • SSH Check: ssh root@72.62.181.194 "pm2 status" (view services)


📊 POST-DEPLOYMENT VERIFICATION
════════════════════════════════════════════════════════════════════════════

Login to VPS and verify:

  ssh root@72.62.181.194

Check services:
  pm2 status                    # See all running services
  pm2 logs                      # View realtime logs
  systemctl status postgresql   # Database status
  curl http://localhost:3000    # Frontend access
  curl http://localhost:4000    # Backend API

View application logs:
  pm2 show reap3r-frontend
  pm2 show reap3r-backend
  pm2 show reap3r-websocket


🔐 DEFAULT CREDENTIALS
════════════════════════════════════════════════════════════════════════════

After deployment:

Application Login:
  Email:    admin@massvision.local
  Password: Admin123!@#

PostgreSQL Database:
  User:     reap3r
  Password: reap3r_secret
  Database: reap3r
  Host:     localhost:5432

SSH Access:
  User:     root
  Method:   SSH key (id_ed25519)


🛠️ TROUBLESHOOTING
════════════════════════════════════════════════════════════════════════════

Q: "Connection refused" when trying to SSH
A: 
  1. Verify SSH key is in authorized_keys on VPS
  2. Check SSH service is running: systemctl status ssh
  3. Verify firewall allows port 22

Q: "npm install fails" during deployment
A:
  1. Check disk space: df -h
  2. Check internet: ping 8.8.8.8
  3. Retry: cd /app/massvision-reap3r && npm install

Q: Database connection fails
A:
  1. Check PostgreSQL: sudo systemctl status postgresql
  2. Verify user exists: sudo -u postgres psql -l
  3. Check /app/massvision-reap3r/.env database connection string

Q: Services not starting
A:
  1. Check PM2: pm2 status (should show 3 green services)
  2. View logs: pm2 logs reap3r-backend
  3. Restart: pm2 restart all

Q: Nginx not proxying correctly
A:
  1. Check config: nginx -t
  2. View logs: tail -f /var/log/nginx/error.log
  3. Restart: systemctl restart nginx


📞 SUPPORT
════════════════════════════════════════════════════════════════════════════

For issues during deployment:
  1. Check logs: pm2 logs
  2. Verify environment: cat /app/massvision-reap3r/.env
  3. Test backend: curl http://localhost:4000/api/auth/me


════════════════════════════════════════════════════════════════════════════
        Ready for deployment! Follow QUICK START section above.
════════════════════════════════════════════════════════════════════════════
