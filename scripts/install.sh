#!/usr/bin/env bash
# ============================================================
# AXELUS — One-Line Installer
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/optimiumnexusllc/AXELUS/main/scripts/install.sh)
# ============================================================
set -euo pipefail

REPO="https://github.com/optimiumnexusllc/AXELUS.git"
INSTALL_DIR="/data/axelus"
COMPOSE_DIR="$(pwd)/AXELUS"
MIN_DOCKER_VERSION="20.10"
MIN_RAM_GB=4

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()    { echo -e "${GREEN}[AXELUS]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
header() { echo -e "\n${BLUE}══════════════════════════════════════${NC}"; echo -e "${BLUE}  $*${NC}"; echo -e "${BLUE}══════════════════════════════════════${NC}\n"; }

# ── Pre-flight checks ────────────────────────────────────────────────────────
header "🛡️  AXELUS WAF Installer"

[ "$(id -u)" -eq 0 ] || error "This script must be run as root (sudo bash install.sh)"

log "Checking system requirements..."

# OS check
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    log "Operating System: $PRETTY_NAME"
else
    warn "Cannot detect OS — proceeding anyway."
fi

# RAM check
RAM_GB=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
if [ "$RAM_GB" -lt "$MIN_RAM_GB" ]; then
    warn "Only ${RAM_GB}GB RAM detected. Minimum recommended: ${MIN_RAM_GB}GB."
fi

# Docker check
if ! command -v docker &>/dev/null; then
    log "Docker not found — installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
fi
log "Docker: $(docker --version)"

# Docker Compose check
if ! docker compose version &>/dev/null; then
    error "Docker Compose v2 not found. Please upgrade Docker."
fi
log "Docker Compose: $(docker compose version --short)"

# ── Clone repository ─────────────────────────────────────────────────────────
header "📦 Cloning AXELUS"

if [ -d "$COMPOSE_DIR" ]; then
    warn "Directory $COMPOSE_DIR already exists. Pulling latest..."
    cd "$COMPOSE_DIR" && git pull
else
    git clone "$REPO" "$COMPOSE_DIR"
    cd "$COMPOSE_DIR"
fi

# ── Configure environment ─────────────────────────────────────────────────────
header "⚙️  Configuration"

if [ ! -f .env ]; then
    cp .env.example .env

    # Auto-generate passwords
    PG_PASS=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 32)
    REDIS_PASS=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 32)
    GRAFANA_PASS=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 32)

    sed -i "s/CHANGE_ME_STRONG_PASSWORD/$PG_PASS/" .env
    sed -i "s/CHANGE_ME_REDIS_PASSWORD/$REDIS_PASS/" .env
    sed -i "s/CHANGE_ME_GRAFANA_PASSWORD/$GRAFANA_PASS/" .env
    sed -i "s|SAFELINE_DIR=.*|SAFELINE_DIR=$INSTALL_DIR|" .env

    log "Auto-generated secure passwords and saved to .env"
    warn "📝 Edit .env to configure optional features (Slack alerts, GeoIP, SIEM, etc.)"
fi

# ── Create data directories ───────────────────────────────────────────────────
header "📁 Creating Data Directories"

mkdir -p "$INSTALL_DIR"/{resources/{mgt,postgres/data,nginx,detector,chaos,cache,sock,luigi},logs/{nginx,detector}}
log "Data directories created at $INSTALL_DIR"

# ── Launch AXELUS ───────────────────────────────────────────────────────────
header "🚀 Launching AXELUS"

# Ask user which stack to start
echo ""
echo "Which components do you want to start?"
echo "  [1] Core only (WAF + database)"
echo "  [2] Core + Monitoring (+ Prometheus + Grafana)"
echo "  [3] Full stack (Core + Monitoring + Premium features)"
read -rp "Enter choice [1-3] (default: 2): " CHOICE
CHOICE="${CHOICE:-2}"

case "$CHOICE" in
    1) COMPOSE_FILES="-f compose.yaml" ;;
    2) COMPOSE_FILES="-f compose.yaml -f compose.monitoring.yaml" ;;
    3) COMPOSE_FILES="-f compose.yaml -f compose.monitoring.yaml -f compose.premium.yaml" ;;
    *) COMPOSE_FILES="-f compose.yaml -f compose.monitoring.yaml" ;;
esac

log "Starting AXELUS with: $COMPOSE_FILES"
docker compose $COMPOSE_FILES up -d

# ── Post-install ──────────────────────────────────────────────────────────────
header "✅ Installation Complete"

SERVER_IP=$(curl -fsSL https://ipv4.icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
INIT_PASS=$(docker logs axelus-mgt 2>/dev/null | grep -i "initial password" | tail -1 | awk '{print $NF}' || echo "(check: docker logs axelus-mgt)")

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      🛡️  AXELUS is up and running!         ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Dashboard:  https://${SERVER_IP}:9443        ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Username:   admin                           ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Password:   ${INIT_PASS}      ${GREEN}║${NC}"
if [[ "$CHOICE" =~ ^[23]$ ]]; then
echo -e "${GREEN}║${NC}  Grafana:    http://${SERVER_IP}:3000         ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Prometheus: http://${SERVER_IP}:9090         ${GREEN}║${NC}"
fi
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
log "Manage AXELUS: cd $COMPOSE_DIR && docker compose ps"
log "View logs:       docker logs axelus-mgt -f"
log "Stop:            docker compose $COMPOSE_FILES down"
echo ""
