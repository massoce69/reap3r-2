#!/bin/bash
# Générer une clé SSH et configurer l'accès
# Exécutez ceci avec Git Bash

set -e

echo "████████████████████████████████████████"
echo "  MASSVISION Reap3r - SSH Configuration"
echo "████████████████████████████████████████"
echo ""

VPS_IP="72.62.181.194"
SSH_KEY_FILE="$HOME/.ssh/reap3r_rsa"

# Générer la clé SSH si elle n'existe pas
if [ ! -f "$SSH_KEY_FILE" ]; then
    echo "[*] Génération de la clé SSH..."
    mkdir -p "$HOME/.ssh"
    ssh-keygen -t ed25519 -f "$SSH_KEY_FILE" -N "" -C "reap3r@vps"
    chmod 600 "$SSH_KEY_FILE"
    echo "[✓] Clé créée: $SSH_KEY_FILE"
else
    echo "[*] Clé SSH existante: $SSH_KEY_FILE"
fi

echo ""
echo "████████████████████████████████████████"
echo "Étapes suivantes:"
echo ""
echo "1. Contactez votre hébergeur et demandez d'ajouter cette clé:"
echo ""
cat "$SSH_KEY_FILE.pub"
echo ""
echo "2. Ou, connectez-vous manuellement:"
echo "   ssh root@$VPS_IP"
echo "   mkdir -p ~/.ssh"
echo "   cat >> ~/.ssh/authorized_keys <<EOF"
cat "$SSH_KEY_FILE.pub"
echo "EOF"
echo "   chmod 600 ~/.ssh/authorized_keys"
echo ""
echo "3. Une fois SShconfiguré, exécutez:"
echo "   bash deploy-auto.sh"
echo ""
