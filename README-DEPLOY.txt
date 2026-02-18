╔════════════════════════════════════════════════════════════════╗
║        MASSVISION Reap3r - DEPLOYMENT COMPLETE ✓                ║
╚════════════════════════════════════════════════════════════════╝

VPS INFO
─────────────────────────────────────────────────────────────────
Server:     72.62.181.194 
User:       root
SSH:        Configure key auth (no password stored in repo)

DEPLOYMENT METHODS (Choose One)
─────────────────────────────────────────────────────────────────

🔵 METHOD 1: Direct SSH (RECOMMENDED)
   ─────────────────────────────────
   ssh root@72.62.181.194
   bash <(curl -sSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/install-prod.sh)

🔵 METHOD 2: One-Line from Windows
   ────────────────────────────────
   "C:\Program Files\Git\bin\bash.exe" deploy-auto.sh

🔵 METHOD 3: Batch Script (Windows)
   ──────────────────────────────────
   C:\Projects\massvision-reap3r\deploy.bat

🔵 METHOD 4: Manual (No Script)
   ─────────────────────────────
   ssh root@72.62.181.194
   apt-get update && apt-get install -y curl
   curl -sSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/install-prod.sh | bash

📋 REQUIRED FILES TO UPDATE
─────────────────────────────────────────────────────────────────
Before deploying, update these scripts with YOUR GitHub URL:

1. install.sh           → Line 50: git clone https://github.com/YOUR_USER/massvision-reap3r.git
2. install-prod.sh      → Line 51: git clone https://github.com/YOUR_USER/massvision-reap3r.git
3. deploy-auto.sh       → Update git clone URL
4. deploy.ps1           → Update GitHub URL

🎯 QUICK DEPLOY (Without SSH Key Setup)
─────────────────────────────────────────────────────────────────
1. SSH into VPS:
   ssh root@72.62.181.194
   (SSH key recommended)

2. Run deployment script:
   bash <(curl -sSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/install-prod.sh)

3. Wait 5-10 minutes for installation

4. Access your application:
   http://72.62.181.194 (Frontend)
   http://72.62.181.194/api/ (API)

✓ WHAT GETS INSTALLED
─────────────────────────────────────────────────────────────────
✓ Node.js v20
✓ PM2 (Process Manager)
✓ PostgreSQL 14+
✓ Nginx (Reverse Proxy)
✓ All npm dependencies
✓ Database migrations
✓ Production builds

📊 SERVICES RUNNING ON VPS
─────────────────────────────────────────────────────────────────
Port 3000  → Frontend (Next.js)
Port 4000  → Backend API (Fastify)
Port 4001  → WebSocket Server
Port 5432  → PostgreSQL Database
Port 80    → Nginx (Public Access)

🔧 USEFUL COMMANDS AFTER DEPLOYMENT
─────────────────────────────────────────────────────────────────
ssh root@72.62.181.194

# Service management
pm2 status                # List all services
pm2 logs                  # View logs in real-time
pm2 restart all           # Restart services
pm2 stop all              # Stop all services
pm2 start all             # Start all services

# Application updates
cd /app/massvision-reap3r
git pull origin main      # Get latest code
npm run build --workspaces  # Rebuild
pm2 restart all           # Restart services

# View specific logs
pm2 logs reap3r-backend
pm2 logs reap3r-frontend

📝 GIT COMMITS READY
─────────────────────────────────────────────────────────────────
✓ 8dc82bc Complete deployment suite with production scripts
✓ 25623cc Add auto-deployment scripts - Ready to execute
✓ 79a3ed3 Finalize deployment scripts - Ready for production
✓ 20b6bd1 Add auto-install script
✓ 14db18e Add quick deployment batch script
✓ d945df5 Add bootstrap deployment and documentation
✓ 855c712 Add deployment scripts for VPS
✓ 995f6e1 Initial commit: MASSVISION Reap3r Enterprise Platform

📁 DEPLOYMENT SCRIPTS LOCATION
─────────────────────────────────────────────────────────────────
C:\Projects\massvision-reap3r\
├── install.sh              ← Production deployment script
├── install-prod.sh         ← Optimized production script
├── deploy-auto.sh          ← Auto-deployment via Git Bash
├── deploy.bat              ← Windows batch launcher
├── deploy.ps1              ← PowerShell deployment
├── setup-ssh.sh            ← SSH key setup script
├── DEPLOYMENT.md           ← Detailed deployment guide
└── DEPLOYMENT-COMPLETE.md  ← Complete reference guide

🚀 NEXT STEPS
─────────────────────────────────────────────────────────────────
1. [ ] Update GitHub URLs in scripts
2. [ ] Push to your GitHub repository
3. [ ] Run deployment script (choose a method above)
4. [ ] Wait for completion
5. [ ] Access http://72.62.181.194
6. [ ] Test login: admin@massvision.local / Admin123!@#
7. [ ] Monitor logs: pm2 logs
8. [ ] (Optional) Configure SSL with Let's Encrypt:
       ssh root@72.62.181.194
       certbot --nginx

⚠️  IMPORTANT NOTES
─────────────────────────────────────────────────────────────────
• VPS SSH key authentication preferred (more secure)
• Update GitHub URLs before deployment
• Database: postgresql://reap3r:reap3r_secret@localhost:5432/reap3r
• All services managed by PM2 with auto-restart on failure
• Nginx reverse proxy handles SSL termination

✓ DEPLOYMENT READY TO GO!
─────────────────────────────────────────────────────────────────
Choose your deployment method above and follow the instructions.

For help: Review DEPLOYMENT-COMPLETE.md
