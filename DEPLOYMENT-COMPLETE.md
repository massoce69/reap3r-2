# 🚀 MASSVISION Reap3r - Deployment Guide

## Quick Start

### Option 1: Direct SSH Deployment (Requires SSH Key)

```bash
ssh root@72.62.181.194 "bash -s" < install-prod.sh
```

### Option 2: One-Line Curl (Simplest)

On your VPS, run:

```bash
bash <(curl -sSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/install-prod.sh)
```

### Option 3: Manual Setup

1. Connect to VPS:
   ```bash
   ssh root@72.62.181.194
   ```

2. Download and run:
   ```bash
   cd /tmp
   curl -sSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/install-prod.sh > install.sh
   bash install.sh
   ```

## Prerequisites

- VPS with Ubuntu 20.04+ (debian-based)
- 2GB+ RAM
- Root or sudo access
- 10GB+ disk space

## Architecture

```
┌─────────────────────────────────────────────┐
│                   Nginx (Port 80)            │
│         (Reverse Proxy / Load Balancer)      │
└──────────────────┬──────────────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
   ┌────▼─────┐        ┌─────▼────┐
   │ Backend   │        │ Frontend  │
   │ (Port     │        │ (Port     │
   │  4000)    │        │  3000)    │
   │ Node.js   │        │ Next.js   │
   │ Fastify   │        │ React     │
   └────┬─────┘        └─────┬────┘
        │                    │
        └────────────┬───────┘
                     │
            ┌────────▼────────┐
            │  PostgreSQL      │
            │  (Port 5432)     │
            │  Database        │
            └─────────────────┘
```

## Services Managed by PM2

- `reap3r-backend` - Fastify API server
- `reap3r-frontend` - Next.js frontend

## Access Points

| Service | URL | Port |
|---------|-----|------|
| Frontend | http://72.62.181.194 | 80 |
| API | http://72.62.181.194/api/ | 80 (proxied) |
| WebSocket | ws://72.62.181.194/ws | 80 (proxied) |
| Backend Direct | http://72.62.181.194:4000 | 4000 |
| Frontend Direct | http://72.62.181.194:3000 | 3000 |

## Post-Deployment

### Check Status

```bash
ssh root@72.62.181.194
pm2 status
pm2 logs
```

### Restart Services

```bash
pm2 restart all
```

### View Logs

```bash
pm2 logs reap3r-backend      # Backend logs
pm2 logs reap3r-frontend     # Frontend logs
pm2 logs                       # All logs
```

### Stop Services

```bash
pm2 stop all
```

### Update Application

```bash
cd /app/massvision-reap3r
git pull origin main
npm run build --workspaces
pm2 restart all
```

## SSL/HTTPS Setup

**(Optional but recommended for production)**

```bash
ssh root@72.62.181.194
certbot --nginx -d yourdomain.com
```

This will:
- Generate SSL certificate
- Configure certificates in Nginx
- Set up auto-renewal

## Troubleshooting

### Services not starting

```bash
pm2 logs
# Check the error messages
```

### Port already in use

```bash
# Find process on port 4000
netstat -tlnp | grep :4000

# Kill it
kill -9 <PID>

# Restart PM2
pm2 restart all
```

### Database connection error

```bash
# Check PostgreSQL
sudo systemctl status postgresql

# Verify credentials
sudo -u postgres psql -d reap3r

# Check environment variables
grep DATABASE_URL /app/massvision-reap3r/backend/.env
```

### Nginx 502 Bad Gateway

```bash
# Check backend is running
curl http://localhost:4000/health

# Check Nginx config
nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

## File Structure on VPS

```
/app/massvision-reap3r/
├── backend/
│   ├── src/
│   ├── .env          (Production environment)
│   ├── package.json
│   └── dist/         (Build output)
├── frontend/
│   ├── src/
│   ├── .env.local    (Frontend config)
│   ├── package.json
│   └── .next/        (Build output)
├── shared/
├── package.json
├── install-prod.sh   (Deployment script)
└── DEPLOYMENT.md     (This file)
```

## Database Backup

```bash
# Backup
sudo -u postgres pg_dump reap3r > reap3r_$(date +%Y%m%d).sql

# Restore
sudo -u postgres psql reap3r < reap3r_20240216.sql
```

## Resource Monitoring

```bash
# View system resources used by PM2 apps
pm2 monit

# View detailed stats
pm2 show reap3r-backend
```

## Common Commands Reference

```bash
# SSH Access
ssh root@72.62.181.194

# Service Management
pm2 list              # List all processes
pm2 status            # Get status
pm2 logs              # View logs
pm2 save              # Save configuration
pm2 startup           # Restore on reboot

# Application Updates
cd /app/massvision-reap3r
git status            # Check for changes
git pull              # Get latest changes
npm ci --workspaces   # Install dependencies
npm run build --workspaces  # Build both frontend & backend
pm2 restart all       # Restart services

# System
systemctl status postgresql   # PostgreSQL status
systemctl status nginx        # Nginx status
systemctl restart nginx       # Restart Nginx
```

## Performance Tips

1. **Enable gzip** compression in Nginx (included)
2. **Use CDN** for static assets (configure in next.config.js)
3. **Monitor** logs regularly for errors
4. **Keep** system packages updated: `apt-get update && apt-get upgrade -y`
5. **Consider** using Redis for caching (future enhancement)

## Support & Debugging

For issues:

1. Check PM2 logs: `pm2 logs`
2. Check Nginx error log: `tail -f /var/log/nginx/error.log`
3. Check PostgreSQL: `systemctl status postgresql`
4. Verify connectivity: `curl http://localhost:3000` and `curl http://localhost:4000/health`

## Next Steps

1. ✅ Deploy using the script above
2. 📝 Configure your domain in Nginx
3. 🔒 Set up SSL with certbot
4. 📊 Set up monitoring (PM2+, New Relic, etc.)
5. 🔄 Schedule backups
6. 📈 Monitor performance and logs

---

**Last Updated**: February 2026  
**Deployment Version**: 1.0  
**Maintained By**: MASSVISION
