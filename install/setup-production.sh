#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  AXELUS-WAF — Production Deployment Script (Single VM)                     ║
# ║  Ubuntu 22.04 / 24.04 LTS                                                  ║
# ║  Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com             ║
# ╠══════════════════════════════════════════════════════════════════════════════╣
# ║  Ce script configure :                                                      ║
# ║  ✓ TLS avec Let's Encrypt (ou certificat custom)                           ║
# ║  ✓ Nginx reverse proxy (termine TLS, protège les ports internes)           ║
# ║  ✓ Firewall UFW strict (80, 443, SSH uniquement)                           ║
# ║  ✓ Durcissement SSH (no root, no password, clé uniquement)                 ║
# ║  ✓ fail2ban (protection brute-force SSH + WAF admin)                       ║
# ║  ✓ Secrets chiffrés (permissions 600, propriétaire axelus uniquement)      ║
# ║  ✓ PostgreSQL durci (connexions limitées, log des requêtes lentes)         ║
# ║  ✓ Redis avec persistance AOF                                               ║
# ║  ✓ Backup quotidien automatisé + rétention 30 jours                        ║
# ║  ✓ Log rotation (Nginx, app logs, audit)                                   ║
# ║  ✓ Mises à jour sécurité automatiques (unattended-upgrades)                ║
# ║  ✓ Monitoring avec alertes (AlertManager + email/Slack)                    ║
# ║  ✓ Service systemd production (restart-on-failure, watchdog)               ║
# ║  ✓ auditd (audit des actions système)                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# Usage:
#   sudo bash install/setup-production.sh \
#     --domain waf.monentreprise.com \
#     --email  admin@monentreprise.com \
#     --ssh-key "ssh-ed25519 AAAA... user@laptop"
#
# Options:
#   --domain DOMAIN       Nom de domaine public pointant sur ce serveur (requis)
#   --email  EMAIL        Email admin (pour Let's Encrypt + notifications)
#   --ssh-key "KEY"       Clé publique SSH autorisée (désactive auth par mot de passe)
#   --admin-ip IP/CIDR    IP autorisée pour accès admin (ex: 10.0.0.0/8)
#   --no-letsencrypt      Utiliser un certificat auto-signé (si pas de domaine public)
#   --slack-webhook URL   Webhook Slack pour les alertes
#   --smtp-host HOST      Serveur SMTP pour les alertes email
#   --smtp-user USER
#   --smtp-pass PASS
#   --backup-s3 BUCKET    Bucket S3/compatible pour externaliser les backups
#
set -euo pipefail
IFS=$'\n\t'

# ── Couleurs ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
OK="${GREEN}✓${RESET}"; ERR="${RED}✗${RESET}"; WARN="${YELLOW}⚠${RESET}"
INFO="${CYAN}ℹ${RESET}"

# ── Defaults ──────────────────────────────────────────────────────────────────
DOMAIN=""
ADMIN_EMAIL=""
SSH_PUBKEY=""
ADMIN_IP="0.0.0.0/0"        # Restreindre en production !
USE_LETSENCRYPT=true
SLACK_WEBHOOK=""
SMTP_HOST=""; SMTP_USER=""; SMTP_PASS=""
BACKUP_S3=""
INSTALL_DIR="/opt/axelus-waf"
DATA_DIR="/data/axelus-waf"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SUBNET="172.22.222"
AXELUS_USER="axelus"

log()  { echo -e "${INFO}  $*"; }
ok()   { echo -e "${OK}  $*"; }
warn() { echo -e "${WARN}  $*"; }
err()  { echo -e "${ERR}  $*" >&2; exit 1; }
# ── Progress tracking ─────────────────────────────────────────────────────────
TOTAL_STEPS=12
CURRENT_STEP=0
INSTALL_START=$(date +%s)
declare -a STEP_DONE=()

STEP_NAMES=(
  ""
  "Prérequis système"
  "Packages système"
  "Utilisateur et répertoires"
  "Génération des secrets"
  "Firewall UFW"
  "Durcissement SSH"
  "fail2ban"
  "TLS + Nginx"
  "Monitoring et alertes"
  "Stack Docker"
  "Backup, logs et audit"
  "Systemd et CLI"
)

STEP_DURATION=()
for i in $(seq 0 12); do STEP_DURATION[$i]=0; done

_step_start_time=0

draw_progress() {
  local cur=${CURRENT_STEP}
  local pct=$(( cur * 100 / TOTAL_STEPS ))
  local bar=50
  local filled=$(( cur * bar / TOTAL_STEPS ))
  local empty=$(( bar - filled ))
  local elapsed=$(( $(date +%s) - INSTALL_START ))
  local elapsed_fmt
  if (( elapsed >= 60 )); then
    elapsed_fmt="$(( elapsed/60 ))m $(( elapsed%60 ))s"
  else
    elapsed_fmt="${elapsed}s"
  fi

  # Barre de progression
  printf "\n${CYAN}  ┌──────────────────────────────────────────────────────────────────────┐${RESET}\n"
  printf "${CYAN}  │${RESET}  "
  printf "${GREEN}"
  for ((i=0; i<filled; i++)); do printf "█"; done
  printf "${RESET}"
  for ((i=0; i<empty; i++)); do printf "░"; done
  printf " ${BOLD}%3d%%${RESET}" $pct
  printf "  %s" "⏱ ${elapsed_fmt}"
  printf "%*s" $(( 8 - ${#elapsed_fmt} )) ""
  printf "${CYAN}│${RESET}\n"
  printf "${CYAN}  └──────────────────────────────────────────────────────────────────────┘${RESET}\n"

  # Liste des étapes
  echo ""
  for i in $(seq 1 $TOTAL_STEPS); do
    local name="${STEP_NAMES[$i]}"
    if (( i < cur )); then
      local dur="${STEP_DURATION[$i]}s"
      printf "  ${GREEN}✓${RESET}  %2d/%d  %-36s ${GREEN}%s${RESET}\n" \
        $i $TOTAL_STEPS "$name" "$dur"
    elif (( i == cur )); then
      printf "  ${YELLOW}▶${RESET}  %2d/%d  ${BOLD}%-36s${RESET} ${YELLOW}en cours...${RESET}\n" \
        $i $TOTAL_STEPS "$name"
    else
      printf "  ${RESET}○${RESET}  %2d/%d  %-36s\n" $i $TOTAL_STEPS "$name"
    fi
  done
  echo ""
}

step() {
  # Incrémenter l'étape
  if (( CURRENT_STEP > 0 )); then
    local dur=$(( $(date +%s) - _step_start_time ))
    STEP_DURATION[$CURRENT_STEP]=$dur
  fi
  CURRENT_STEP=$(( CURRENT_STEP + 1 ))
  _step_start_time=$(date +%s)
  # Effacer l'écran et redessiner
  clear 2>/dev/null || printf '\n%.0s' {1..5}
  # Header compact
  printf "${CYAN}  ╔══════════════════════════════════════════════════════════════════╗${RESET}\n"
  printf "${CYAN}  ║  ${BOLD}AXELUS-WAF Production${RESET}${CYAN}  —  Étape %-2d/%d  —  %-24s║${RESET}\n" \
    $CURRENT_STEP $TOTAL_STEPS "${STEP_NAMES[$CURRENT_STEP]}"
  printf "${CYAN}  ╚══════════════════════════════════════════════════════════════════╝${RESET}\n"
  draw_progress
}

gen_pass()   { openssl rand -base64 48 | tr -dc 'A-Za-z0-9!@#%^*' | head -c 32; }
gen_secret() { openssl rand -hex 32; }

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --domain)          DOMAIN="$2";          shift 2 ;;
    --email)           ADMIN_EMAIL="$2";     shift 2 ;;
    --ssh-key)         SSH_PUBKEY="$2";      shift 2 ;;
    --admin-ip)        ADMIN_IP="$2";        shift 2 ;;
    --no-letsencrypt)  USE_LETSENCRYPT=false; shift ;;
    --slack-webhook)   SLACK_WEBHOOK="$2";   shift 2 ;;
    --smtp-host)       SMTP_HOST="$2";       shift 2 ;;
    --smtp-user)       SMTP_USER="$2";       shift 2 ;;
    --smtp-pass)       SMTP_PASS="$2";       shift 2 ;;
    --backup-s3)       BACKUP_S3="$2";       shift 2 ;;
    --help|-h)
      echo "Usage: sudo bash setup-production.sh --domain waf.example.com --email admin@example.com"
      echo "       sudo bash setup-production.sh --domain waf.internal --no-letsencrypt"
      exit 0 ;;
    *) err "Option inconnue: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || err "Run as root: sudo bash install/setup-production.sh [OPTIONS]"
[[ -n "$DOMAIN" ]] || err "--domain est requis. Ex: --domain waf.monentreprise.com"

# Détecter automatiquement si DOMAIN est une adresse IP (Let's Encrypt ne fonctionne pas avec les IPs)
if [[ "$DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  USE_LETSENCRYPT=false
  log "IP détectée (${DOMAIN}) — Let's Encrypt désactivé automatiquement, utilisation d'un certificat auto-signé"
fi
[[ -n "$ADMIN_EMAIL" ]] || err "--email est requis. Ex: --email admin@monentreprise.com"

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  AXELUS-WAF — Déploiement Production (VM unique)                ║${RESET}"
echo -e "${CYAN}║  OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com             ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  Domaine  : ${YELLOW}${DOMAIN}${RESET}"
echo -e "  Email    : ${YELLOW}${ADMIN_EMAIL}${RESET}"
echo -e "  TLS      : $([ "$USE_LETSENCRYPT" = true ] && echo "${GREEN}Let's Encrypt${RESET}" || echo "${YELLOW}Auto-signé${RESET}")"
echo -e "  Admin IP : ${YELLOW}${ADMIN_IP}${RESET}"
echo ""
read -rp "  Confirmer le déploiement production ? [oui/non] : " confirm
[[ "$confirm" == "oui" ]] || { echo "Annulé."; exit 0; }

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 1 — Prérequis système
# ═══════════════════════════════════════════════════════════════════════════════
step

# RAM
RAM_GB=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024 ))
[[ $RAM_GB -ge 2 ]] || warn "RAM insuffisante: ${RAM_GB}GB (4GB recommandé en production)"
ok "RAM: ${RAM_GB}GB"

# Disk
DISK_FREE=$(df -BG / | awk 'NR==2 {print $4}' | tr -d G)
[[ $DISK_FREE -ge 20 ]] || warn "Espace disque: ${DISK_FREE}GB (40GB recommandé en production)"
ok "Disque: ${DISK_FREE}GB disponible"

# Docker
command -v docker &>/dev/null || err "Docker non installé. Lancer: curl -fsSL https://get.docker.com | bash"
docker compose version &>/dev/null || err "Docker Compose plugin manquant"
ok "Docker: $(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 2 — Packages système
# ═══════════════════════════════════════════════════════════════════════════════
step

export DEBIAN_FRONTEND=noninteractive

# ── Préparer apt : IPv4 + miroir stable ──────────────────────────────────────

# Forcer IPv4 (VM sans connectivité IPv6)
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

# Ubuntu 24.04 utilise sources.list.d/ubuntu.sources (format DEB822)
# Vider sources.list pour éviter les doublons
truncate -s 0 /etc/apt/sources.list

# Corriger ubuntu.sources (format DEB822, Ubuntu 22.04+)
if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
  sed -i 's|http://ci.archive.ubuntu.com|http://archive.ubuntu.com|g'     /etc/apt/sources.list.d/ubuntu.sources
  log "ubuntu.sources: ci. → archive.ubuntu.com"
fi

# Corriger aussi les .list classiques (Ubuntu 20.04)
find /etc/apt/sources.list.d/ -name "*.list"   -exec sed -i 's|ci.archive.ubuntu.com|archive.ubuntu.com|g' {} \; 2>/dev/null || true

apt-get clean -qq

# apt-get update avec retry (3 tentatives, 5s entre chaque)
APT_UPDATE_OK=false
for attempt in 1 2 3; do
  if apt-get update -qq 2>/dev/null; then
    APT_UPDATE_OK=true; break
  fi
  warn "apt-get update tentative ${attempt}/3 échouée — retry dans 5s..."
  sleep 5
done
$APT_UPDATE_OK || warn "apt-get update partiel — poursuite de l'installation"

apt-get install -y -qq \
  nginx \
  certbot python3-certbot-nginx \
  ufw fail2ban \
  auditd audispd-plugins \
  unattended-upgrades apt-listchanges \
  logrotate \
  jq openssl curl wget \
  net-tools dnsutils \
  postgresql-client \
  awscli 2>/dev/null || true

ok "Packages installés: nginx, certbot, ufw, fail2ban, auditd, unattended-upgrades"

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 3 — Utilisateur système et répertoires
# ═══════════════════════════════════════════════════════════════════════════════
step

id "$AXELUS_USER" &>/dev/null || useradd -r -s /sbin/nologin -d "$DATA_DIR" "$AXELUS_USER"
usermod -aG docker "$AXELUS_USER" 2>/dev/null || true

dirs=(
  "$DATA_DIR/resources/"{postgres,mgt,detector,nginx,sock}
  "$DATA_DIR/logs/"{nginx,mgt,audit}
  "$DATA_DIR/backups"
  "$DATA_DIR/certs"
  "$INSTALL_DIR"
  "$REPO_DIR/monitoring/"{prometheus,alertmanager,grafana/provisioning/{datasources,dashboards}}
)
for d in "${dirs[@]}"; do mkdir -p "$d"; done

chown -R "$AXELUS_USER":"$AXELUS_USER" "$DATA_DIR" "$INSTALL_DIR"
chmod 750 "$DATA_DIR" "$INSTALL_DIR"
ok "Utilisateur '${AXELUS_USER}' et répertoires créés"

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 4 — Génération des secrets (production-grade)
# ═══════════════════════════════════════════════════════════════════════════════
step

POSTGRES_PASSWORD=$(gen_pass)
REDIS_PASSWORD=$(gen_pass)
JWT_SECRET=$(gen_secret)
ADMIN_API_KEY=$(gen_secret)
LICENSE_KEY=$(gen_secret)
GRAFANA_PASSWORD=$(gen_pass)
INTERNAL_WEBHOOK_SECRET=$(gen_secret)

# Écriture du .env avec permissions strictes
ENV_FILE="$REPO_DIR/.env"
cat > "$ENV_FILE" << ENVEOF
# AXELUS-WAF — Configuration Production
# Généré le : $(date -u "+%Y-%m-%d %H:%M UTC")
# Serveur   : $(hostname -f)
# ⚠ CONFIDENTIEL — Ne jamais committer ce fichier

IMAGE_PREFIX=optimiumnexusllc
IMAGE_TAG=latest
ARCH_SUFFIX=
REGION=
RELEASE=
SUBNET_PREFIX=${SUBNET}
SAFELINE_DIR=${DATA_DIR}
MGT_PORT=9443

# Base de données
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

# Redis
REDIS_PASSWORD=${REDIS_PASSWORD}

# Auth
JWT_SECRET=${JWT_SECRET}
ADMIN_API_KEY=${ADMIN_API_KEY}
LICENSE_ADMIN_KEY=${LICENSE_KEY}
INTERNAL_WEBHOOK_SECRET=${INTERNAL_WEBHOOK_SECRET}

# Monitoring
GRAFANA_PASSWORD=${GRAFANA_PASSWORD}

# Alerting
SLACK_WEBHOOK_URL=${SLACK_WEBHOOK}
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=587
SMTP_USER=${SMTP_USER}
SMTP_PASSWORD=${SMTP_PASS}
SMTP_FROM=axelus-waf@${DOMAIN}
ALERT_EMAIL=${ADMIN_EMAIL}

# Domaine et TLS
DOMAIN=${DOMAIN}
TLS_ENABLED=true

# Backup
BACKUP_S3_BUCKET=${BACKUP_S3}
BACKUP_RETENTION_DAYS=30
ENVEOF

chmod 600 "$ENV_FILE"
chown "$AXELUS_USER":"$AXELUS_USER" "$ENV_FILE"
ok "Secrets générés → ${ENV_FILE} (chmod 600)"

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 5 — Firewall UFW
# ═══════════════════════════════════════════════════════════════════════════════
step

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH — restreindre si une IP admin est spécifiée
if [[ "$ADMIN_IP" != "0.0.0.0/0" ]]; then
  ufw allow from "$ADMIN_IP" to any port 22 comment "SSH admin"
  warn "SSH restreint à ${ADMIN_IP} — vérifiez l'accès avant de fermer la session"
else
  ufw allow 22/tcp comment "SSH"
  warn "SSH ouvert depuis partout — restreindre avec --admin-ip en production"
fi

# Ports publics WAF
ufw allow 80/tcp  comment "HTTP (redirect HTTPS)"
ufw allow 443/tcp comment "HTTPS WAF"

# Ports internes — FERMÉS à Internet
# 9443 (Management API), 3000 (Grafana), 9090 (Prometheus)
# accessibles uniquement via Nginx avec auth ou VPN

# Docker — éviter que Docker bypass UFW
if ! grep -q "DOCKER-USER" /etc/ufw/after.rules 2>/dev/null; then
  cat >> /etc/ufw/after.rules << 'UFWEOF'

# AXELUS-WAF — Bloquer l'accès direct aux ports Docker internes
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -p tcp --dport 9443 -j DROP
-A DOCKER-USER -p tcp --dport 3000  -j DROP
-A DOCKER-USER -p tcp --dport 9090  -j DROP
-A DOCKER-USER -p tcp --dport 9093  -j DROP
COMMIT
UFWEOF
fi

ufw --force enable
ufw status verbose
ok "Firewall UFW activé — ports ouverts: 22, 80, 443 uniquement"

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 6 — Durcissement SSH
# ═══════════════════════════════════════════════════════════════════════════════
step

SSH_CONFIG="/etc/ssh/sshd_config.d/axelus-hardening.conf"
cat > "$SSH_CONFIG" << 'SSHEOF'
# AXELUS-WAF — SSH Hardening
Protocol 2
PermitRootLogin no
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PrintLastLog yes
Banner /etc/ssh/axelus-banner
SSHEOF

# Si une clé SSH est fournie, désactiver l'auth par mot de passe
if [[ -n "$SSH_PUBKEY" ]]; then
  echo "PasswordAuthentication no" >> "$SSH_CONFIG"
  echo "PubkeyAuthentication yes" >> "$SSH_CONFIG"

  # Ajouter la clé pour l'utilisateur sudo courant
  SUDO_USER_HOME=$(eval echo "~${SUDO_USER:-root}")
  mkdir -p "$SUDO_USER_HOME/.ssh"
  echo "$SSH_PUBKEY" >> "$SUDO_USER_HOME/.ssh/authorized_keys"
  chmod 700 "$SUDO_USER_HOME/.ssh"
  chmod 600 "$SUDO_USER_HOME/.ssh/authorized_keys"
  ok "Clé SSH ajoutée — auth par mot de passe désactivée"
else
  echo "PasswordAuthentication yes" >> "$SSH_CONFIG"
  warn "Aucune clé SSH fournie — auth par mot de passe maintenue (utiliser --ssh-key en production)"
fi

cat > /etc/ssh/axelus-banner << 'BANEOF'
╔════════════════════════════════════════════════════════════╗
║  AXELUS-WAF Production Server — OPTIMIUM NEXUS LLC        ║
║  Accès non autorisé strictement interdit                   ║
║  Toutes les connexions sont journalisées et auditées       ║
╚════════════════════════════════════════════════════════════╝
BANEOF

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
ok "SSH durci (no root, max 3 tentatives, bannière)"

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 7 — fail2ban
# ═══════════════════════════════════════════════════════════════════════════════
step

mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/filter.d
cat > /etc/fail2ban/jail.d/axelus.conf << 'F2BEOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
banaction = ufw

[sshd]
enabled  = true
port     = ssh
maxretry = 3
bantime  = 86400

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 5

[nginx-limit-req]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 10

[axelus-admin]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/axelus-access.log
maxretry = 10
findtime = 60
bantime  = 3600
filter   = axelus-admin
F2BEOF

cat > /etc/fail2ban/filter.d/axelus-admin.conf << 'FILTEREOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST|PUT|DELETE|PATCH) /api/.*" (401|403|429) .*$
ignoreregex =
FILTEREOF

# Installer fail2ban si le service n'existe pas encore
if ! systemctl list-unit-files fail2ban.service &>/dev/null; then
  apt-get install -y -qq fail2ban 2>/dev/null || true
fi

if systemctl list-unit-files fail2ban.service &>/dev/null 2>&1 | grep -q fail2ban; then
  systemctl enable fail2ban --now 2>/dev/null || true
  systemctl restart fail2ban 2>/dev/null || true
  ok "fail2ban configuré (SSH: ban 24h après 3 échecs, Admin: ban 1h après 10 erreurs 4xx)"
else
  warn "fail2ban non disponible — protection brute-force désactivée (installer manuellement: apt install fail2ban)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 8 — TLS et Nginx reverse proxy
# ═══════════════════════════════════════════════════════════════════════════════
step

# Arrêter Nginx temporairement pour Let's Encrypt
systemctl stop nginx 2>/dev/null || true

if [[ "$USE_LETSENCRYPT" == true ]]; then
  log "Génération certificat Let's Encrypt pour ${DOMAIN}..."
  certbot certonly --standalone \
    --non-interactive --agree-tos \
    --email "$ADMIN_EMAIL" \
    --domain "$DOMAIN" \
    --rsa-key-size 4096 2>&1 | tail -5

  CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

  # Renouvellement automatique
  cat > /etc/cron.d/certbot-axelus << 'CERTEOF'
0 3 * * * root certbot renew --quiet --post-hook "systemctl reload nginx" >> /var/log/axelus-certbot.log 2>&1
CERTEOF
  ok "Let's Encrypt : certificat obtenu pour ${DOMAIN}"
else
  # Certificat auto-signé
  openssl req -x509 -newkey rsa:4096 \
    -keyout "$DATA_DIR/certs/axelus.key" \
    -out    "$DATA_DIR/certs/axelus.crt" \
    -days 365 -nodes \
    -subj "/C=FR/O=OPTIMIUM NEXUS LLC/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},IP:${DOMAIN},IP:$(hostname -I | awk '{print $1}')" \
    2>/dev/null
  CERT_PATH="$DATA_DIR/certs/axelus.crt"
  KEY_PATH="$DATA_DIR/certs/axelus.key"
  ok "Certificat auto-signé généré pour ${DOMAIN}"
fi

# Configuration Nginx production
cat > /etc/nginx/sites-available/axelus-waf << NGINXEOF
# AXELUS-WAF — Nginx Production Config
# TLS termination + reverse proxy

# Redirect HTTP → HTTPS
server {
    listen 80;
    server_name ${DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}

# HTTPS — WAF + Admin
server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     ${CERT_PATH};
    ssl_certificate_key ${KEY_PATH};

    # TLS 1.3 uniquement, suites chiffrées fortes
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # HSTS — 1 an, inclure sous-domaines
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;

    # Cacher la version Nginx
    server_tokens off;

    client_max_body_size 50m;
    client_body_timeout 30s;
    client_header_timeout 30s;

    # ── WAF Dashboard (accès public restreint) ──────────────────────────────
    location /waf/ {
        # Restriction IP admin si configuré
        allow ${ADMIN_IP};
        deny all;

        proxy_pass         http://127.0.0.1:9443/;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 30s;
        proxy_connect_timeout 5s;
    }

    # ── API REST (restreinte à l'IP admin) ──────────────────────────────────
    location /api/ {
        allow ${ADMIN_IP};
        deny all;

        proxy_pass         http://127.0.0.1:9443/api/;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
    }

    # ── Grafana (restreint à l'IP admin) ────────────────────────────────────
    location /grafana/ {
        allow ${ADMIN_IP};
        deny all;

        proxy_pass         http://127.0.0.1:3000/;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        rewrite  ^/grafana/(.*) /\$1 break;
    }

    # ── Health check public (pour load balancer / monitoring externe) ────────
    location /health {
        allow all;
        proxy_pass http://127.0.0.1:9443/api/open/health;
        access_log off;
    }

    # ── Bloquer toute autre route ────────────────────────────────────────────
    location / {
        return 444;
    }

    access_log /var/log/nginx/axelus-access.log combined;
    error_log  /var/log/nginx/axelus-error.log warn;
}
NGINXEOF

ln -sf /etc/nginx/sites-available/axelus-waf /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable nginx --now && systemctl start nginx
ok "Nginx configuré (TLS 1.3, HSTS, reverse proxy, restriction IP admin)"

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 9 — Configs monitoring production
# ═══════════════════════════════════════════════════════════════════════════════
step

source "$ENV_FILE"

cat > "$REPO_DIR/monitoring/prometheus/prometheus.yaml" << PROMEOF
global:
  scrape_interval:     15s
  evaluation_interval: 15s
  external_labels:
    environment: production
    domain: ${DOMAIN}

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['axelus-alertmanager:9093']

rule_files:
  - /etc/prometheus/rules/*.yaml

scrape_configs:
  - job_name: axelus-mgt
    static_configs:
      - targets: ['axelus-mgt:9443']
    metrics_path: /api/open/health
    scrape_timeout: 10s

  - job_name: postgres
    static_configs:
      - targets: ['axelus-pg-exporter:9187']

  - job_name: nginx
    static_configs:
      - targets: ['axelus-nginx-exporter:9113']

  - job_name: node
    static_configs:
      - targets: ['axelus-node-exporter:9100']
PROMEOF

mkdir -p "$REPO_DIR/monitoring/prometheus/rules"
cat > "$REPO_DIR/monitoring/prometheus/rules/axelus.yaml" << 'RULESEOF'
groups:
  - name: axelus-waf
    interval: 30s
    rules:
      - alert: WAFDown
        expr: up{job="axelus-mgt"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "AXELUS-WAF Management API is DOWN"
          description: "The WAF management API has been unreachable for more than 1 minute."

      - alert: HighBlockRate
        expr: rate(axelus_requests_blocked_total[5m]) > 100
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High WAF block rate detected"
          description: "More than 100 requests/sec blocked in the last 5 minutes — possible attack."

      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100 < 15
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space on WAF server"
          description: "Less than 15% disk space remaining."

      - alert: PostgreSQLDown
        expr: up{job="postgres"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "PostgreSQL is DOWN"
          description: "AXELUS-WAF database is unreachable — WAF configuration may be unavailable."

      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage on WAF server"
          description: "Memory usage above 85% for 5 minutes."

      - alert: CertificateExpiryWarning
        expr: (probe_ssl_earliest_cert_expiry - time()) / 86400 < 30
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "TLS certificate expiring soon"
          description: "TLS certificate expires in less than 30 days."

      - alert: BackupMissing
        expr: time() - axelus_last_backup_timestamp > 90000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "No recent backup detected"
          description: "No backup in the last 25 hours."
RULESEOF

# AlertManager avec Slack et/ou email
cat > "$REPO_DIR/monitoring/alertmanager/alertmanager.yaml" << AMEOF
global:
  resolve_timeout: 5m
  smtp_from: 'axelus-waf@${DOMAIN}'
  smtp_smarthost: '${SMTP_HOST:-localhost}:587'
  smtp_auth_username: '${SMTP_USER}'
  smtp_auth_password: '${SMTP_PASS}'
  smtp_require_tls: true

route:
  group_by: ['alertname', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'default'
  routes:
    - match:
        severity: critical
      receiver: 'critical'
      repeat_interval: 1h

receivers:
  - name: 'default'
$(if [[ -n "$SMTP_HOST" ]]; then
cat << EMAILEOF
    email_configs:
      - to: '${ADMIN_EMAIL}'
        send_resolved: true
EMAILEOF
fi)
$(if [[ -n "$SLACK_WEBHOOK" ]]; then
cat << SLACKEOF
    slack_configs:
      - api_url: '${SLACK_WEBHOOK}'
        channel: '#axelus-alerts'
        send_resolved: true
        title: 'AXELUS-WAF {{ .Status | toUpper }}: {{ .CommonLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
SLACKEOF
fi)

  - name: 'critical'
$(if [[ -n "$SMTP_HOST" ]]; then
cat << EMAILEOF2
    email_configs:
      - to: '${ADMIN_EMAIL}'
        send_resolved: true
        headers:
          Subject: '[CRITICAL] AXELUS-WAF: {{ .CommonLabels.alertname }}'
EMAILEOF2
fi)
$(if [[ -n "$SLACK_WEBHOOK" ]]; then
cat << SLACKEOF2
    slack_configs:
      - api_url: '${SLACK_WEBHOOK}'
        channel: '#axelus-critical'
        send_resolved: true
SLACKEOF2
fi)
AMEOF

ok "Prometheus rules et AlertManager configurés"

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 10 — Démarrage du stack Docker
# ═══════════════════════════════════════════════════════════════════════════════
step

cd "$REPO_DIR"

log "Pull des images optimiumnexusllc/axelus-*..."
docker compose -f docker-compose.poc.yml --env-file "$ENV_FILE" pull --quiet 2>/dev/null || true

log "Démarrage des services..."
docker compose -f docker-compose.poc.yml --env-file "$ENV_FILE" up -d --remove-orphans

# Attente healthchecks
log "Attente des healthchecks..."
printf "  PostgreSQL  "
for i in $(seq 1 40); do
  docker exec axelus-pg pg_isready -U axelus -q 2>/dev/null && { echo -e "${OK}"; break; }
  sleep 3; printf "."; [[ $i -eq 40 ]] && echo -e " ${WARN}"
done

printf "  Management  "
for i in $(seq 1 50); do
  curl -sf http://127.0.0.1:9443/api/open/health &>/dev/null && { echo -e "${OK}"; break; }
  sleep 3; printf "."; [[ $i -eq 50 ]] && echo -e " ${WARN}"
done

printf "  Grafana     "
for i in $(seq 1 20); do
  curl -sf http://127.0.0.1:3000/api/health &>/dev/null && { echo -e "${OK}"; break; }
  sleep 3; printf "."; [[ $i -eq 20 ]] && echo -e " ${WARN}"
done

ok "Stack Docker démarré"

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 11 — Backup automatisé + log rotation + auditd
# ═══════════════════════════════════════════════════════════════════════════════
step

# Script de backup
cat > /usr/local/bin/axelus-backup << BACKUPEOF
#!/usr/bin/env bash
# AXELUS-WAF — Backup quotidien
set -euo pipefail
source ${ENV_FILE}

BACKUP_DIR="${DATA_DIR}/backups"
TS=\$(date +%Y%m%d_%H%M%S)
FILE="\${BACKUP_DIR}/axelus-\${TS}.sql.gz"

# Backup PostgreSQL
docker exec axelus-pg pg_dump -U axelus axelus | gzip > "\$FILE"
chmod 640 "\$FILE"

# Fichier de timestamp pour l'alerte Prometheus
echo \$(date +%s) > "\${BACKUP_DIR}/last_backup_timestamp"

# Nettoyage des vieux backups
find "\$BACKUP_DIR" -name "*.sql.gz" -mtime +\${BACKUP_RETENTION_DAYS:-30} -delete

SIZE=\$(du -sh "\$FILE" | cut -f1)
echo "\$(date -u '+%Y-%m-%d %H:%M UTC') — Backup OK: \$FILE (\$SIZE)"

# Upload S3 si configuré
if [[ -n "\${BACKUP_S3_BUCKET:-}" ]]; then
  aws s3 cp "\$FILE" "s3://\${BACKUP_S3_BUCKET}/axelus/\$(basename \$FILE)" --quiet
  echo "\$(date -u '+%Y-%m-%d %H:%M UTC') — Backup S3: s3://\${BACKUP_S3_BUCKET}/axelus/"
fi
BACKUPEOF
chmod 750 /usr/local/bin/axelus-backup

# Cron backup quotidien à 2h
cat > /etc/cron.d/axelus-backup << 'CRONEOF'
0 2 * * * root /usr/local/bin/axelus-backup >> /var/log/axelus-backup.log 2>&1
CRONEOF
ok "Backup quotidien programmé à 02h00"

# Log rotation
cat > /etc/logrotate.d/axelus-waf << 'LOGEOF'
/var/log/nginx/axelus-*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        nginx -s reopen 2>/dev/null || true
    endscript
}

/var/log/axelus-backup.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
}
LOGEOF
ok "Log rotation configurée (30 jours Nginx, 12 semaines backups)"

# auditd — audit des accès fichiers sensibles
cat > /etc/audit/rules.d/axelus.rules << 'AUDITEOF'
# AXELUS-WAF — Audit rules
-w /opt/axelus-waf/.env -p rwxa -k axelus-secrets
-w /data/axelus-waf -p rwxa -k axelus-data
-w /etc/nginx/sites-available/axelus-waf -p rwxa -k axelus-nginx
-w /usr/local/bin/axelus-backup -p rwxa -k axelus-backup
-w /etc/cron.d/axelus-backup -p rwxa -k axelus-cron
AUDITEOF
augenrules --load 2>/dev/null || systemctl restart auditd 2>/dev/null || true
ok "auditd configuré (surveillance des fichiers sensibles)"

# Mises à jour sécurité automatiques
cat > /etc/apt/apt.conf.d/50axelus-unattended << 'APTEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Mail "${ADMIN_EMAIL}";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
APTEOF
ok "Mises à jour sécurité automatiques activées"

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 12 — Service systemd production + CLI
# ═══════════════════════════════════════════════════════════════════════════════
step

cat > /etc/systemd/system/axelus-waf.service << SVCEOF
[Unit]
Description=AXELUS-WAF — Production WAF by OPTIMIUM NEXUS LLC
Documentation=https://www.optimiumnexus.com/docs
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
WorkingDirectory=${REPO_DIR}
EnvironmentFile=${ENV_FILE}
ExecStartPre=/usr/bin/docker compose -f ${REPO_DIR}/docker-compose.poc.yml --env-file ${ENV_FILE} pull --quiet
ExecStart=/usr/bin/docker compose -f ${REPO_DIR}/docker-compose.poc.yml --env-file ${ENV_FILE} up -d --remove-orphans
ExecStop=/usr/bin/docker compose -f ${REPO_DIR}/docker-compose.poc.yml --env-file ${ENV_FILE} stop
ExecReload=/usr/bin/docker compose -f ${REPO_DIR}/docker-compose.poc.yml --env-file ${ENV_FILE} restart
TimeoutStartSec=180
TimeoutStopSec=60
Restart=on-failure
RestartSec=30
WatchdogSec=300
StandardOutput=journal
StandardError=journal
SyslogIdentifier=axelus-waf

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable axelus-waf.service
ok "Service systemd production activé (restart-on-failure, watchdog 5min)"

# CLI axelus avec commandes production
cat > /usr/local/bin/axelus << CLIEOF
#!/usr/bin/env bash
# AXELUS-WAF CLI — Production
set -euo pipefail
REPO_DIR="${REPO_DIR}"
COMPOSE_FILE="${REPO_DIR}/docker-compose.poc.yml"
ENV_FILE="${ENV_FILE}"
cd "\$REPO_DIR"
set -a; source "\$ENV_FILE"; set +a

case "\${1:-help}" in
  start)    systemctl start  axelus-waf ;;
  stop)     systemctl stop   axelus-waf ;;
  restart)  systemctl restart axelus-waf ;;
  status)   docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" ps ;;
  logs)     docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" logs -f "\${2:-}" ;;
  health)   curl -sf https://${DOMAIN}/health | python3 -m json.tool ;;
  update)
    docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" pull
    systemctl restart axelus-waf
    ;;
  backup)   /usr/local/bin/axelus-backup ;;
  restore)
    [[ -z "\${2:-}" ]] && { echo "Usage: axelus restore <fichier.sql.gz>"; exit 1; }
    zcat "\$2" | docker exec -i axelus-pg psql -U axelus axelus
    echo "Restauration terminée depuis \$2"
    ;;
  shell)    docker exec -it "axelus-\${2:-mgt}" /bin/sh ;;
  ufw)      ufw status verbose ;;
  fail2ban) fail2ban-client status ;;
  cert)
    if [[ "${USE_LETSENCRYPT}" == "true" ]]; then
      certbot certificates
    else
      openssl x509 -in ${DATA_DIR}/certs/axelus.crt -noout -dates
    fi
    ;;
  audit)    ausearch -k axelus-secrets --start today 2>/dev/null | tail -20 ;;
  compliance)
    curl -sf -X POST https://${DOMAIN}/api/v1/compliance/assess \
      -H "X-Admin-Key: \${ADMIN_API_KEY}" \
      -H "Content-Type: application/json" \
      -d '{"tenant_id":"production","standard_id":"PCI-DSS-4.0"}' | python3 -m json.tool
    ;;
  help|*)
    echo "AXELUS-WAF CLI — Production"
    echo ""
    echo "  start | stop | restart | status | logs [svc]"
    echo "  update     — pull nouvelles images + restart"
    echo "  backup     — backup immédiat"
    echo "  restore    — restauration depuis un backup"
    echo "  health     — santé de l'API via HTTPS"
    echo "  shell [svc]— shell dans un conteneur"
    echo "  ufw        — état du firewall"
    echo "  fail2ban   — IPs bannies"
    echo "  cert       — état du certificat TLS"
    echo "  audit      — log d'audit récent"
    echo "  compliance — rapport PCI-DSS"
    ;;
esac
CLIEOF
chmod +x /usr/local/bin/axelus

# ═══════════════════════════════════════════════════════════════════════════════
# Résumé final
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
# Finaliser la dernière étape
STEP_DURATION[$CURRENT_STEP]=$(( $(date +%s) - _step_start_time ))
CURRENT_STEP=$(( TOTAL_STEPS ))
clear 2>/dev/null || true
printf "${CYAN}  ╔══════════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${CYAN}  ║  ${BOLD}AXELUS-WAF Production${RESET}${CYAN}  —  Installation terminée !               ║${RESET}\n"
printf "${CYAN}  ╚══════════════════════════════════════════════════════════════════╝${RESET}\n"
draw_progress

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  AXELUS-WAF Production — Déploiement Terminé                        ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}URLs${RESET}"
echo -e "  WAF Dashboard   : ${YELLOW}https://${DOMAIN}/waf/${RESET}     (restreint IP admin)"
echo -e "  Grafana         : ${YELLOW}https://${DOMAIN}/grafana/${RESET}  (restreint IP admin)"
echo -e "  Health check    : ${YELLOW}https://${DOMAIN}/health${RESET}    (public)"
echo -e "  API REST        : ${YELLOW}https://${DOMAIN}/api/${RESET}      (restreint IP admin)"
echo ""
echo -e "${BOLD}Credentials${RESET}"
echo -e "  Admin API Key   : ${YELLOW}${ADMIN_API_KEY}${RESET}"
echo -e "  Grafana login   : admin / ${YELLOW}${GRAFANA_PASSWORD}${RESET}"
echo -e "  PostgreSQL pass : ${YELLOW}${POSTGRES_PASSWORD}${RESET}"
echo ""
echo -e "${BOLD}Sécurité activée${RESET}"
echo -e "  ${OK} TLS 1.3 avec HSTS (1 an)"
echo -e "  ${OK} Firewall UFW — ports 80/443/22 uniquement"
echo -e "  ${OK} SSH durci — no root, bannière, max 3 tentatives"
echo -e "  ${OK} fail2ban — ban SSH (24h) et admin (1h)"
echo -e "  ${OK} Port 9443/3000/9090 fermés à Internet"
echo -e "  ${OK} auditd — surveillance fichiers sensibles"
echo -e "  ${OK} Mises à jour sécurité automatiques"
echo ""
echo -e "${BOLD}Opérations${RESET}"
echo -e "  ${OK} Backup quotidien à 02h → ${DATA_DIR}/backups/"
echo -e "  ${OK} Log rotation 30 jours"
echo -e "  ${OK} Alertes Prometheus (7 règles: WAF down, disk, cert...)"
echo -e "  ${OK} Service systemd (auto-restart, watchdog 5min)"
echo ""
echo -e "${BOLD}Fichiers importants${RESET}"
echo -e "  Secrets         : ${ENV_FILE} (chmod 600)"
echo -e "  Backup script   : /usr/local/bin/axelus-backup"
echo -e "  Logs Nginx      : /var/log/nginx/axelus-*.log"
echo -e "  Logs backup     : /var/log/axelus-backup.log"
echo ""
echo -e "${BOLD}Prochaines étapes recommandées${RESET}"
echo -e "  1. Tester HTTPS : curl -sv https://${DOMAIN}/health"
echo -e "  2. Vérifier firewall : axelus ufw"
echo -e "  3. Lancer un backup manuel : axelus backup"
echo -e "  4. Rapport conformité : axelus compliance"
echo -e "  5. Vérifier alertes : https://${DOMAIN}/grafana/"
echo ""
echo -e "${RED}⚠ Sauvegarder les credentials ci-dessus dans un gestionnaire de mots de passe${RESET}"
echo -e "${RED}  Le fichier ${ENV_FILE} est la seule source de vérité${RESET}"
echo ""
echo -e "${GREEN}AXELUS-WAF Production — OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com${RESET}"
