# MASSVISION Reap3r - Guide de Déploiement

## Déploiement Rapide en Une Commande

Connectez-vous à votre VPS et exécutez:

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/bootstrap.sh)
```

**Remplacez** `yourusername` par votre nom d'utilisateur GitHub.

## Déploiement Manuel

### 1. Préparer la Clé SSH (depuis Windows)

```powershell
# Générer une clé SSH si vous n'en avez pas
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\id_ed25519

# Copier la clé publique
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub | Set-Clipboard

# Ajouter à VPS (une seule fois)
# Connectez-vous avec le mot de passe et:
# mkdir -p ~/.ssh
# echo "VOTRE_CLE_PUBLIQUE" >> ~/.ssh/authorized_keys
# chmod 600 ~/.ssh/authorized_keys
```

### 2. Connexion SSH

```bash
ssh root@72.62.181.194
```

### 3. Exécuter le Bootstrap

```bash
cd /tmp
curl -fsSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/bootstrap.sh > bootstrap.sh
sudo bash bootstrap.sh
```

### 4. Configuration DNS (optionnel)

Pointez votre domaine vers l'IP du VPS:

```
A record: massvision.local -> 72.62.181.194
```

### 5. SSL avec Let's Encrypt (optionnel)

```bash
sudo certbot --nginx -d massvision.local
```

## Services

Tous les services fonctionnent via PM2:

```bash
# Voir le statut
pm2 status

# Voir les logs
pm2 logs

# Redémarrer
pm2 restart all

# Arrêter
pm2 stop all

# Démarrer
pm2 start all
```

## URLs d'Accès

- **Frontend**: http://72.62.181.194
- **API**: http://72.62.181.194/api/
- **WebSocket**: ws://72.62.181.194/ws

## Dépannage

### Backend ne démarre pas

```bash
pm2 logs reap3r-backend
```

### Base de données

```bash
# Se connecter
sudo -u postgres psql -d reap3r

# Vérifier les utilisateurs
SELECT * FROM pg_user;

# Lister les tables
\dt
```

### Nginx ne reroute pas

```bash
# Vérifier la configuration
sudo nginx -t

# Redémarrer
sudo systemctl restart nginx

# Voir les erreurs
sudo tail -f /var/log/nginx/error.log
```

## Mise à Jour

```bash
cd /app/massvision-reap3r
git pull origin main
npm run build --workspaces
pm2 restart all
```

## Sauvegarde

```bash
# Sauvegarder la base de données
sudo -u postgres pg_dump reap3r > backup_$(date +%Y%m%d).sql

# Sauvegarder l'app
tar -czf app_backup_$(date +%Y%m%d).tar.gz /app/massvision-reap3r
```

## Configuration de Domaine Personnalisé

Modifiez `/etc/nginx/sites-available/reap3r-prod`:

```nginx
server {
    server_name mon-domaine.com www.mon-domaine.com;
    # ... reste de la config
}
```

Puis redémarrez Nginx:

```bash
sudo systemctl restart nginx
```

## Logs d'Erreurs Courants

### "Connection refused" sur 4000/3000

Le service n'est pas démarré. Vérifiez:

```bash
pm2 logs
ps aux | grep node
netstat -tlnp | grep :4000
```

### "Database error"

La PostgreSQL n'est pas accessible:

```bash
sudo systemctl start postgresql
export DATABASE_URL="postgresql://reap3r:reap3r_secret@localhost:5432/reap3r"
```

### Nginx "502 Bad Gateway"

Vérifiez que les services backend/frontend sont actifs:

```bash
pm2 status
curl http://localhost:3000
curl http://localhost:4000/health
```

## Support

Pour toute aide:

1. Consultez les logs: `pm2 logs`
2. Vérifiez que tous les services sont actifs
3. Testez les ports: `netstat -tlnp`
4. Consultez la documentation complète: [docs/](./docs/)
