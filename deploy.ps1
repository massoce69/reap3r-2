#!/usr/bin/env pwsh
# Deployment en 1 ligne

$IP = "72.62.181.194"
$CMD = 'bash <(curl -sSL https://raw.githubusercontent.com/yourusername/massvision-reap3r/main/install.sh)'

Write-Host "
████████████████████████████████████████
  MASSVISION Reap3r - VPS Deployment
████████████████████████████████████████
Serveur: $IP
" -ForegroundColor Cyan

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    Write-Host "SSH non disponible. Installez Git: https://gitforwindows.org/" -ForegroundColor Red
    exit 1
}

ssh -o ConnectTimeout=10 root@$IP $CMD
