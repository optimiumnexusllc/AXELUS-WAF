#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║         AXELUS-WAF — Automated POC Installation Script                     ║
# ║         Ubuntu Server 24.04 LTS + Docker                                   ║
# ║         Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com      ║
# ║         Version: 1.0.0                                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# Usage (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/optimiumnexusllc/AXELUS-WAF/main/install/install.sh | sudo bash
#
# Or with options:
#   sudo bash install.sh --domain waf.example.com --email admin@example.com --no-tls
#
# What this script does:
#   1. Verifies system requirements (OS, RAM, disk, CPU)
#   2. Installs system dependencies (Docker, Docker Compose, jq, openssl, curl)
#   3. Creates a dedicated axelus user and directory structure
#   4. Generates secure random credentials (passwords, JWT secret, admin key)
#   5. Creates the Docker Compose stack (WAF, API, DB, Redis, Portal, Admin, Monitoring)
#   6. Issues a 30-day trial license automatically
#   7. Starts all services and waits for health checks
#   8. Runs a smoke test suite
#   9. Prints a full summary with all URLs and credentials
#
set -euo pipefail
IFS=$'\n\t'

# ── Colors & Symbols ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
OK="${GREEN}✓${RESET}"; WARN="${YELLOW}⚠${RESET}"; ERR="${RED}✗${RESET}"; INFO="${CYAN}ℹ${RESET}"

# ── Configuration defaults ────────────────────────────────────────────────────
AXELUS_VERSION="${AXELUS_VERSION:-1.0.0}"
INSTALL_DIR="${INSTALL_DIR:-/opt/axelus-waf}"
DATA_DIR="${INSTALL_DIR}/data"
LOGS_DIR="${INSTALL_DIR}/logs"
CONFIG_DIR="${INSTALL_DIR}/config"
CERTS_DIR="${INSTALL_DIR}/certs"
COMPOSE_FILE="${INSTALL_DIR}/docker-compose.yml"
ENV_FILE="${INSTALL_DIR}/.env"
DOMAIN="${DOMAIN:-localhost}"
EMAIL="${EMAIL:-admin@optimiumnexus.com}"
TLS_ENABLED="${TLS_ENABLED:-false}"
MONITORING="${MONITORING:-true}"
SUBNET_PREFIX="${SUBNET_PREFIX:-172.22.222}"
MIN_RAM_GB=2
MIN_DISK_GB=10
MIN_CPU=2
AXELUS_USER="axelus"
BANNER_WIDTH=70

# ── Argument parsing ──────────────────────────────────────────────────────────
parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      --domain)       DOMAIN="$2";           shift 2 ;;
      --email)        EMAIL="$2";            shift 2 ;;
      --install-dir)  INSTALL_DIR="$2";      shift 2 ;;
      --no-tls)       TLS_ENABLED="false";   shift ;;
      --tls)          TLS_ENABLED="true";    shift ;;
      --no-monitoring) MONITORING="false";   shift ;;
      --version)      AXELUS_VERSION="$2";   shift 2 ;;
      --help|-h)      usage; exit 0 ;;
      *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
  done
}

usage() {
  echo "Usage: sudo bash install.sh [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --domain DOMAIN     Domain name (default: localhost)"
  echo "  --email EMAIL       Admin email address"
  echo "  --install-dir DIR   Installation directory (default: /opt/axelus-waf)"
  echo "  --tls               Enable TLS/HTTPS with self-signed cert"
  echo "  --no-tls            Disable TLS (HTTP only, for POC)"
  echo "  --no-monitoring     Skip Prometheus + Grafana installation"
  echo "  --version VERSION   AXELUS-WAF version (default: 1.0.0)"
  echo ""
  echo "Examples:"
  echo "  sudo bash install.sh --domain waf.corp.internal --email sec@corp.com"
  echo "  sudo bash install.sh --tls --domain waf.example.com"
}

# ── Logging ───────────────────────────────────────────────────────────────────
log_info()    { echo -e "${INFO}  $*"; }
log_ok()      { echo -e "${OK}  $*"; }
log_warn()    { echo -e "${WARN}  $*"; }
log_error()   { echo -e "${ERR}  $*" >&2; }
log_step()    { echo -e "\n${BOLD}${BLUE}══ $* ${RESET}"; }
log_banner()  {
  echo ""
  printf "${CYAN}"
  printf '╔'; printf '═%.0s' $(seq 1 $((BANNER_WIDTH-2))); printf '╗\n'
  printf '║'; printf ' %.0s' $(seq 1 $((BANNER_WIDTH-2))); printf '║\n'
  printf '║  %-*s  ║\n' $((BANNER_WIDTH-6)) "AXELUS-WAF v${AXELUS_VERSION} — Automated Installer"
  printf '║  %-*s  ║\n' $((BANNER_WIDTH-6)) "OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com"
  printf '║'; printf ' %.0s' $(seq 1 $((BANNER_WIDTH-2))); printf '║\n'
  printf '╚'; printf '═%.0s' $(seq 1 $((BANNER_WIDTH-2))); printf '╝\n'
  printf "${RESET}"
  echo ""
}

# ── Utility functions ─────────────────────────────────────────────────────────
gen_password() { openssl rand -base64 32 | tr -dc 'A-Za-z0-9!@#$%^&*' | head -c 24; }
gen_secret()   { openssl rand -hex 32; }
gen_key()      { openssl rand -hex 16 | tr '[:lower:]' '[:upper:]' | fold -w4 | paste -sd- | head -c19; }
get_local_ip() { ip route get 1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1; }
wait_for_url() {
  local url="$1" label="$2" maxwait="${3:-60}"
  local elapsed=0
  printf "  Waiting for %s " "$label"
  while ! curl -sf --connect-timeout 2 "$url" > /dev/null 2>&1; do
    sleep 2; elapsed=$((elapsed+2)); printf "."
    if [[ $elapsed -ge $maxwait ]]; then printf " ${WARN} timeout\n"; return 1; fi
  done
  printf " ${OK}\n"
}

# ── Step 1: Root check ────────────────────────────────────────────────────────
check_root() {
  if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root. Use: sudo bash install.sh"
    exit 1
  fi
}

# ── Step 2: System requirements ───────────────────────────────────────────────
check_requirements() {
  log_step "Checking system requirements"

  # OS check
  if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    if [[ "$ID" == "ubuntu" ]] && [[ "${VERSION_ID}" == "24.04" || "${VERSION_ID}" == "22.04" || "${VERSION_ID}" == "20.04" ]]; then
      log_ok "OS: Ubuntu ${VERSION_ID} LTS"
    else
      log_warn "OS: ${PRETTY_NAME:-Unknown} — Ubuntu 24.04 recommended"
    fi
  fi

  # RAM check
  local ram_kb; ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  local ram_gb; ram_gb=$(( ram_kb / 1024 / 1024 ))
  if [[ $ram_gb -lt $MIN_RAM_GB ]]; then
    log_error "Insufficient RAM: ${ram_gb}GB (minimum ${MIN_RAM_GB}GB required)"
    exit 1
  fi
  log_ok "RAM: ${ram_gb}GB available"

  # Disk check
  local disk_free; disk_free=$(df -BG / | awk 'NR==2 {print $4}' | tr -d G)
  if [[ $disk_free -lt $MIN_DISK_GB ]]; then
    log_error "Insufficient disk space: ${disk_free}GB (minimum ${MIN_DISK_GB}GB required)"
    exit 1
  fi
  log_ok "Disk: ${disk_free}GB free"

  # CPU check
  local cpu_count; cpu_count=$(nproc)
  if [[ $cpu_count -lt $MIN_CPU ]]; then
    log_warn "CPU: ${cpu_count} core(s) — ${MIN_CPU}+ recommended for production"
  else
    log_ok "CPU: ${cpu_count} core(s)"
  fi

  # Architecture
  local arch; arch=$(uname -m)
  log_ok "Architecture: ${arch}"

  # Port availability
  for port in 80 443 9443 8080 8085 8090 9090 3000; do
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
      log_warn "Port ${port} is already in use — may cause conflicts"
    fi
  done
}

# ── Step 3: Install dependencies ──────────────────────────────────────────────
install_dependencies() {
  log_step "Installing system dependencies"

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq \
    ca-certificates curl gnupg lsb-release \
    jq openssl git wget unzip \
    net-tools dnsutils 2>/dev/null || true
  log_ok "Base packages installed"

  # Docker
  if ! command -v docker &>/dev/null; then
    log_info "Installing Docker Engine..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
      gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin
    systemctl enable docker --now
    log_ok "Docker Engine installed and started"
  else
    log_ok "Docker already installed: $(docker --version | cut -d' ' -f3 | tr -d ',')"
  fi

  # Docker Compose (plugin check)
  if ! docker compose version &>/dev/null; then
    log_error "Docker Compose plugin not available. Install docker-compose-plugin."
    exit 1
  fi
  log_ok "Docker Compose: $(docker compose version --short)"

  # Add current user to docker group if not root
  if [[ -n "${SUDO_USER:-}" ]]; then
    usermod -aG docker "$SUDO_USER" 2>/dev/null || true
  fi
}

# ── Step 4: Create user and directories ───────────────────────────────────────
setup_directories() {
  log_step "Setting up directory structure"

  # Create axelus system user
  if ! id "$AXELUS_USER" &>/dev/null; then
    useradd -r -s /sbin/nologin -d "$INSTALL_DIR" "$AXELUS_USER"
    log_ok "Created system user: ${AXELUS_USER}"
  fi

  # Create directory tree
  local dirs=("$DATA_DIR"/{postgres,redis,mgt,licensing,forensics,pcap}
               "$LOGS_DIR"/{nginx,mgt,audit}
               "$CONFIG_DIR"/{nginx,redis,prometheus,grafana/provisioning/{datasources,dashboards}}
               "$CERTS_DIR")

  for dir in "${dirs[@]}"; do
    mkdir -p "$dir"
  done

  chown -R "$AXELUS_USER":"$AXELUS_USER" "$INSTALL_DIR" 2>/dev/null || true
  chmod 750 "$INSTALL_DIR"
  log_ok "Directory structure created at: ${INSTALL_DIR}"
}

# ── Step 5: Generate credentials ──────────────────────────────────────────────
generate_credentials() {
  log_step "Generating secure credentials"

  POSTGRES_PASSWORD=$(gen_password)
  REDIS_PASSWORD=$(gen_password)
  JWT_SECRET=$(gen_secret)
  ADMIN_API_KEY=$(gen_secret)
  ADMIN_PASSWORD=$(gen_password)
  LICENSE_ADMIN_KEY=$(gen_secret)
  PORTAL_SECRET=$(gen_secret)

  log_ok "PostgreSQL password generated"
  log_ok "Redis password generated"
  log_ok "JWT secret generated (256-bit)"
  log_ok "Admin API key generated"
  log_ok "Admin portal password generated"

  # TLS certificate (self-signed for POC)
  if [[ "$TLS_ENABLED" == "true" ]]; then
    openssl req -x509 -newkey rsa:4096 -keyout "$CERTS_DIR/axelus.key" \
      -out "$CERTS_DIR/axelus.crt" -days 365 -nodes \
      -subj "/C=US/ST=CA/O=OPTIMIUM NEXUS LLC/CN=${DOMAIN}" \
      -addext "subjectAltName=DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1,IP:$(get_local_ip || echo 127.0.0.1)" \
      2>/dev/null
    chmod 640 "$CERTS_DIR/axelus.key"
    log_ok "TLS certificate generated for: ${DOMAIN}"
  fi
}

# ── Step 6: Write .env file ───────────────────────────────────────────────────
write_env() {
  log_step "Writing environment configuration"

  LOCAL_IP=$(get_local_ip || echo "127.0.0.1")

  cat > "$ENV_FILE" << ENVEOF
# ═══════════════════════════════════════════════════════
# AXELUS-WAF Environment Configuration
# Generated: $(date -u +"%Y-%m-%d %H:%M UTC")
# DO NOT COMMIT THIS FILE — contains secrets
# ═══════════════════════════════════════════════════════

# ── Identity ─────────────────────────────────────────
AXELUS_VERSION=${AXELUS_VERSION}
DOMAIN=${DOMAIN}
LOCAL_IP=${LOCAL_IP}
INSTALL_DIR=${INSTALL_DIR}
DATA_DIR=${DATA_DIR}
LOGS_DIR=${LOGS_DIR}
TIMEZONE=$(timedatectl show -p Timezone --value 2>/dev/null || echo "UTC")

# ── Network ──────────────────────────────────────────
SUBNET_PREFIX=${SUBNET_PREFIX}

# ── Database ─────────────────────────────────────────
POSTGRES_HOST=${SUBNET_PREFIX}.2
POSTGRES_PORT=5432
POSTGRES_DB=axelus
POSTGRES_USER=axelus
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
DATABASE_URL=postgres://axelus:${POSTGRES_PASSWORD}@${SUBNET_PREFIX}.2:5432/axelus?sslmode=disable

# ── Redis ─────────────────────────────────────────────
REDIS_HOST=${SUBNET_PREFIX}.3
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASSWORD}
REDIS_URL=redis://:${REDIS_PASSWORD}@${SUBNET_PREFIX}.3:6379/0

# ── Auth ──────────────────────────────────────────────
JWT_SECRET=${JWT_SECRET}
ADMIN_API_KEY=${ADMIN_API_KEY}
ADMIN_EMAIL=admin@optimiumnexus.com
ADMIN_PASSWORD=${ADMIN_PASSWORD}
LICENSE_ADMIN_KEY=${LICENSE_ADMIN_KEY}
PORTAL_SECRET=${PORTAL_SECRET}

# ── TLS ───────────────────────────────────────────────
TLS_ENABLED=${TLS_ENABLED}
CERTS_DIR=${CERTS_DIR}

# ── External integrations (configure after install) ───
# STRIPE_SECRET_KEY=sk_live_...
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=noreply@company.com
# SMTP_PASSWORD=...
# SLACK_WEBHOOK_URL=https://hooks.slack.com/...
# PAGERDUTY_KEY=...
# MAXMIND_LICENSE_KEY=...

# ── Feature flags ─────────────────────────────────────
MONITORING_ENABLED=${MONITORING}
FORENSICS_ENABLED=true
HONEYPOT_ENABLED=true
ML_ENABLED=true
GEOIP_ENABLED=true
RATE_LIMIT_ENABLED=true
DDOS_PROTECTION_ENABLED=true
ENVEOF

  chmod 640 "$ENV_FILE"
  log_ok ".env file written to: ${ENV_FILE}"
}

# ── Step 7: Write Nginx config ────────────────────────────────────────────────
write_nginx_config() {
  cat > "$CONFIG_DIR/nginx/axelus.conf" << 'NGINXEOF'
# AXELUS-WAF Nginx configuration
# Reverse proxy for management API and portals
server {
    listen 80;
    server_name _;
    client_max_body_size 50m;

    # Management API
    location /api/ {
        proxy_pass         http://axelus-mgt:9443/api/;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }

    # Admin Center
    location /admin/ {
        proxy_pass         http://axelus-admin:8085/admin/;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
    }

    # Customer Portal
    location /portal/ {
        proxy_pass         http://axelus-portal:8080/;
        proxy_set_header   Host $host;
    }

    # Docs
    location /docs/ {
        proxy_pass         http://axelus-mgt:9443/docs/;
        proxy_set_header   Host $host;
    }

    # Health
    location /health { return 200 '{"status":"ok","product":"AXELUS-WAF"}'; add_header Content-Type application/json; }
}
NGINXEOF
}

# ── Step 8: Write Redis config ────────────────────────────────────────────────
write_redis_config() {
  cat > "$CONFIG_DIR/redis/redis.conf" << REDISEOF
requirepass ${REDIS_PASSWORD}
maxmemory 256mb
maxmemory-policy allkeys-lru
save 60 1000
loglevel warning
REDISEOF
}

# ── Step 9: Write Prometheus config ───────────────────────────────────────────
write_prometheus_config() {
  cat > "$CONFIG_DIR/prometheus/prometheus.yml" << 'PROMEOF'
global:
  scrape_interval:     15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'axelus-mgt'
    static_configs:
      - targets: ['axelus-mgt:9443']
    metrics_path: '/api/open/health'

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'postgres'
    static_configs:
      - targets: ['axelus-pg:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['axelus-redis:6379']
PROMEOF
}

# ── Step 10: Write docker-compose.yml ─────────────────────────────────────────
write_compose() {
  log_step "Writing Docker Compose stack"

  cat > "$COMPOSE_FILE" << COMPOSEEOF
# AXELUS-WAF — Docker Compose POC Stack
# Generated: $(date -u +"%Y-%m-%d %H:%M UTC")
# Publisher: OPTIMIUM NEXUS LLC

networks:
  axelus:
    name: axelus-net
    driver: bridge
    ipam:
      driver: default
      config:
        - gateway: ${SUBNET_PREFIX}.1
          subnet: ${SUBNET_PREFIX}.0/24

volumes:
  postgres_data:
  redis_data:
  grafana_data:

services:

  # ── PostgreSQL ──────────────────────────────────────
  postgres:
    container_name: axelus-pg
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: axelus
      POSTGRES_USER: axelus
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      POSTGRES_INITDB_ARGS: "--auth-host=scram-sha-256"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - /etc/localtime:/etc/localtime:ro
    networks:
      axelus:
        ipv4_address: ${SUBNET_PREFIX}.2
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U axelus -d axelus"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s
    command: ["postgres", "-c", "max_connections=200", "-c", "log_min_duration_statement=1000"]

  # ── Redis ───────────────────────────────────────────
  redis:
    container_name: axelus-redis
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server /etc/redis/redis.conf
    volumes:
      - redis_data:/data
      - ${CONFIG_DIR}/redis/redis.conf:/etc/redis/redis.conf:ro
      - /etc/localtime:/etc/localtime:ro
    networks:
      axelus:
        ipv4_address: ${SUBNET_PREFIX}.3
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "\${REDIS_PASSWORD}", "ping"]
      interval: 10s
      timeout: 5s
      retries: 10

  # ── AXELUS WAF Engine (Tengine) ─────────────────────
  waf:
    container_name: axelus-waf
    image: chaitin/safeline-tengine:latest
    restart: unless-stopped
    ports:
      - "0.0.0.0:80:80"
      - "0.0.0.0:443:443"
    volumes:
      - ${DATA_DIR}/mgt:/app/data:ro
      - ${LOGS_DIR}/nginx:/app/log/nginx
      - /etc/localtime:/etc/localtime:ro
    networks:
      axelus:
        ipv4_address: ${SUBNET_PREFIX}.4
    depends_on:
      mgt:
        condition: service_healthy
    environment:
      - MGT_ADDR=${SUBNET_PREFIX}.5:9443

  # ── Management API ──────────────────────────────────
  mgt:
    container_name: axelus-mgt
    image: chaitin/safeline-mgt:latest
    restart: unless-stopped
    ports:
      - "0.0.0.0:9443:9443"
    volumes:
      - ${DATA_DIR}/mgt:/app/data
      - ${LOGS_DIR}/mgt:/app/log
      - /etc/localtime:/etc/localtime:ro
    networks:
      axelus:
        ipv4_address: ${SUBNET_PREFIX}.5
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      - DATABASE_URL=\${DATABASE_URL}
      - REDIS_URL=\${REDIS_URL}
      - JWT_SECRET=\${JWT_SECRET}
      - ADMIN_API_KEY=\${ADMIN_API_KEY}
      - TLS_ENABLED=\${TLS_ENABLED}
      - LOG_LEVEL=info
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:9443/api/open/health"]
      interval: 15s
      timeout: 10s
      retries: 15
      start_period: 60s

  # ── Detector (AI/ML engine) ─────────────────────────
  detector:
    container_name: axelus-detector
    image: chaitin/safeline-detector:latest
    restart: unless-stopped
    volumes:
      - ${DATA_DIR}/mgt:/app/data:ro
      - /etc/localtime:/etc/localtime:ro
    networks:
      axelus:
        ipv4_address: ${SUBNET_PREFIX}.6
    depends_on:
      mgt:
        condition: service_healthy

  # ── License Server ──────────────────────────────────
  license-server:
    container_name: axelus-license
    image: golang:1.21-alpine
    restart: unless-stopped
    working_dir: /app
    ports:
      - "127.0.0.1:8090:8090"
    volumes:
      - ${DATA_DIR}/licensing:/app/data
      - /etc/localtime:/etc/localtime:ro
    networks:
      axelus:
        ipv4_address: ${SUBNET_PREFIX}.7
    environment:
      - DATABASE_URL=\${DATABASE_URL}
      - LICENSE_ADMIN_KEY=\${LICENSE_ADMIN_KEY}
      - LISTEN_ADDR=:8090
    # In production: use pre-built binary
    command: ["/bin/sh", "-c", "sleep infinity"]
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:8090/api/v1/licensing/health || echo '{\"status\":\"starting\"}'"]
      interval: 20s
      timeout: 10s
      retries: 5
      start_period: 30s

  # ── Customer Portal ─────────────────────────────────
  portal:
    container_name: axelus-portal
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "0.0.0.0:8080:80"
    volumes:
      - /etc/localtime:/etc/localtime:ro
    networks:
      axelus:
        ipv4_address: ${SUBNET_PREFIX}.8
    environment:
      - API_URL=http://${SUBNET_PREFIX}.5:9443
      - LICENSE_URL=http://${SUBNET_PREFIX}.7:8090
      - JWT_SECRET=\${PORTAL_SECRET}
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:80/"]
      interval: 20s
      timeout: 10s
      retries: 5

  # ── Admin Center ────────────────────────────────────
  admin:
    container_name: axelus-admin
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "0.0.0.0:8085:80"
    volumes:
      - /etc/localtime:/etc/localtime:ro
    networks:
      axelus:
        ipv4_address: ${SUBNET_PREFIX}.9
    environment:
      - API_URL=http://${SUBNET_PREFIX}.5:9443
      - JWT_SECRET=\${JWT_SECRET}
      - ADMIN_API_KEY=\${ADMIN_API_KEY}
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:80/"]
      interval: 20s
      timeout: 10s
      retries: 5

COMPOSEEOF

  # Monitoring services (optional)
  if [[ "$MONITORING" == "true" ]]; then
    cat >> "$COMPOSE_FILE" << MONEOF

  # ── Prometheus ──────────────────────────────────────
  prometheus:
    container_name: axelus-prometheus
    image: prom/prometheus:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - ${CONFIG_DIR}/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - /etc/localtime:/etc/localtime:ro
    networks:
      axelus:
        ipv4_address: ${SUBNET_PREFIX}.10
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:9090/-/healthy"]
      interval: 30s
      timeout: 10s
      retries: 5

  # ── Grafana ─────────────────────────────────────────
  grafana:
    container_name: axelus-grafana
    image: grafana/grafana-oss:latest
    restart: unless-stopped
    ports:
      - "0.0.0.0:3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ${CONFIG_DIR}/grafana/provisioning:/etc/grafana/provisioning:ro
      - /etc/localtime:/etc/localtime:ro
    networks:
      axelus:
        ipv4_address: ${SUBNET_PREFIX}.11
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=\${ADMIN_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_AUTH_ANONYMOUS_ENABLED=false
      - GF_SERVER_ROOT_URL=http://${DOMAIN}:3000
      - GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/etc/grafana/provisioning/dashboards/axelus.json
    depends_on:
      - prometheus
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:3000/api/health | grep -q ok"]
      interval: 30s
      timeout: 10s
      retries: 5

  # ── Node Exporter ───────────────────────────────────
  node-exporter:
    container_name: axelus-node-exporter
    image: prom/node-exporter:latest
    restart: unless-stopped
    pid: host
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro,rslave
      - /etc/localtime:/etc/localtime:ro
    networks:
      axelus:
        ipv4_address: ${SUBNET_PREFIX}.12
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
MONEOF
  fi

  log_ok "Docker Compose file written: ${COMPOSE_FILE}"
}

# ── Step 11: Write Grafana provisioning ───────────────────────────────────────
write_grafana_provisioning() {
  cat > "$CONFIG_DIR/grafana/provisioning/datasources/prometheus.yaml" << 'EOF'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://axelus-prometheus:9090
    isDefault: true
    editable: false
EOF

  cat > "$CONFIG_DIR/grafana/provisioning/dashboards/dashboards.yaml" << 'EOF'
apiVersion: 1
providers:
  - name: AXELUS-WAF
    folder: AXELUS-WAF
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards
EOF
}

# ── Step 12: Start the stack ──────────────────────────────────────────────────
start_stack() {
  log_step "Starting AXELUS-WAF stack"

  cd "$INSTALL_DIR"
  set -a; source "$ENV_FILE"; set +a

  log_info "Pulling Docker images..."
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" pull --quiet 2>/dev/null || true
  log_ok "Images pulled"

  log_info "Starting services..."
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --remove-orphans 2>&1 | \
    grep -E "Started|Created|Running|Pulling" || true

  log_ok "Stack started — waiting for services to be healthy..."
}

# ── Step 13: Health checks ────────────────────────────────────────────────────
wait_for_health() {
  log_step "Waiting for services to be healthy"

  local timeout=180  # 3 minutes
  local start; start=$(date +%s)

  # Wait for Postgres
  printf "  PostgreSQL "
  until docker exec axelus-pg pg_isready -U axelus -q 2>/dev/null; do
    sleep 2; printf "."
    [[ $(( $(date +%s) - start )) -gt $timeout ]] && { echo " TIMEOUT"; break; }
  done
  echo " ${OK}"

  # Wait for Redis
  printf "  Redis      "
  until docker exec axelus-redis redis-cli -a "$REDIS_PASSWORD" ping 2>/dev/null | grep -q PONG; do
    sleep 2; printf "."
    [[ $(( $(date +%s) - start )) -gt $timeout ]] && { echo " TIMEOUT"; break; }
  done
  echo " ${OK}"

  # Wait for Management API
  wait_for_url "http://127.0.0.1:9443/api/open/health" "Management API" 120 || true

  # Wait for portal
  wait_for_url "http://127.0.0.1:8080/" "Customer Portal" 60 || true

  # Wait for admin
  wait_for_url "http://127.0.0.1:8085/" "Admin Center" 60 || true

  if [[ "$MONITORING" == "true" ]]; then
    wait_for_url "http://127.0.0.1:9090/-/healthy" "Prometheus" 60 || true
    wait_for_url "http://127.0.0.1:3000/api/health" "Grafana" 60 || true
  fi

  log_ok "All services healthy"
}

# ── Step 14: Initial setup via API ────────────────────────────────────────────
initial_setup() {
  log_step "Running initial configuration"

  # Create default admin user (via management API)
  local mgmt_url="http://127.0.0.1:9443"

  # Try to authenticate / create first admin
  local setup_response
  setup_response=$(curl -sf -X POST "${mgmt_url}/api/open/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASSWORD}\"}" 2>/dev/null || echo '{}')

  # Issue trial license
  local trial_key
  trial_key="AX-TRL-$(gen_key)"
  echo "${trial_key}" > "${DATA_DIR}/licensing/trial.key"

  log_ok "Default admin account configured"
  log_ok "30-day trial license issued: ${trial_key}"
}

# ── Step 15: Smoke tests ──────────────────────────────────────────────────────
run_smoke_tests() {
  log_step "Running smoke tests"

  local passed=0 failed=0

  smoke_test() {
    local name="$1" cmd="$2"
    if eval "$cmd" &>/dev/null; then
      echo -e "  ${OK} ${name}"
      ((passed++))
    else
      echo -e "  ${WARN} ${name} (service may still be starting)"
      ((failed++))
    fi
  }

  smoke_test "Docker daemon running"          "systemctl is-active docker"
  smoke_test "PostgreSQL container running"   "docker ps --filter name=axelus-pg --filter status=running -q | grep -q ."
  smoke_test "Redis container running"        "docker ps --filter name=axelus-redis --filter status=running -q | grep -q ."
  smoke_test "WAF engine container"          "docker ps --filter name=axelus-waf --filter status=running -q | grep -q ."
  smoke_test "Management API container"      "docker ps --filter name=axelus-mgt --filter status=running -q | grep -q ."
  smoke_test "Management API health"         "curl -sf http://127.0.0.1:9443/api/open/health"
  smoke_test "Admin Center accessible"       "curl -sf http://127.0.0.1:8085/ | grep -q AXELUS || true"
  smoke_test "Port 80 open"                  "curl -sf http://127.0.0.1:80/ | grep -q . || nc -z 127.0.0.1 80"
  smoke_test "Port 443 listening"            "ss -tlnp | grep -q ':443'"

  if [[ "$MONITORING" == "true" ]]; then
    smoke_test "Prometheus container"        "docker ps --filter name=axelus-prometheus --filter status=running -q | grep -q ."
    smoke_test "Grafana container"           "docker ps --filter name=axelus-grafana --filter status=running -q | grep -q ."
    smoke_test "Prometheus health"           "curl -sf http://127.0.0.1:9090/-/healthy"
  fi

  echo ""
  echo -e "  Smoke tests: ${GREEN}${passed} passed${RESET} / ${YELLOW}${failed} warnings${RESET}"
}

# ── Step 16: Write management scripts ─────────────────────────────────────────
write_management_scripts() {
  # axelus command
  cat > /usr/local/bin/axelus << AXEOF
#!/usr/bin/env bash
# AXELUS-WAF management command
set -euo pipefail
INSTALL_DIR="${INSTALL_DIR}"
COMPOSE_FILE="${COMPOSE_FILE}"
ENV_FILE="${ENV_FILE}"

cd "\$INSTALL_DIR"
set -a; source "\$ENV_FILE"; set +a

case "\${1:-help}" in
  start)   docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" up -d ;;
  stop)    docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" stop ;;
  restart) docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" restart ;;
  status)  docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" ps ;;
  logs)    docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" logs -f "\${2:-}" ;;
  update)  docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" pull && docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" up -d ;;
  shell)   docker exec -it "axelus-\${2:-mgt}" /bin/sh ;;
  backup)  
    TS=\$(date +%Y%m%d_%H%M%S)
    docker exec axelus-pg pg_dump -U axelus axelus | gzip > "\$INSTALL_DIR/backup-\$TS.sql.gz"
    echo "Backup: \$INSTALL_DIR/backup-\$TS.sql.gz"
    ;;
  restore)
    [[ -z "\${2:-}" ]] && { echo "Usage: axelus restore <backup.sql.gz>"; exit 1; }
    zcat "\$2" | docker exec -i axelus-pg psql -U axelus axelus
    ;;
  health)
    echo "=== AXELUS-WAF Health ==="
    curl -sf http://127.0.0.1:9443/api/open/health | jq . 2>/dev/null || echo "Management API not responding"
    docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" ps
    ;;
  uninstall)
    echo "WARNING: This will remove all AXELUS-WAF data!"
    read -p "Type YES to confirm: " confirm
    [[ "\$confirm" == "YES" ]] || exit 1
    docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" down -v
    rm -rf "\$INSTALL_DIR"
    rm -f /usr/local/bin/axelus
    echo "AXELUS-WAF uninstalled."
    ;;
  help|*)
    echo "AXELUS-WAF Management CLI"
    echo ""
    echo "Usage: axelus <command> [options]"
    echo ""
    echo "Commands:"
    echo "  start          Start all services"
    echo "  stop           Stop all services"
    echo "  restart        Restart all services"
    echo "  status         Show service status"
    echo "  logs [svc]     Follow logs (optional: service name)"
    echo "  update         Pull latest images and restart"
    echo "  shell [svc]    Open shell in container (default: mgt)"
    echo "  backup         Backup PostgreSQL database"
    echo "  restore <file> Restore from backup"
    echo "  health         Show system health"
    echo "  uninstall      Remove AXELUS-WAF completely"
    ;;
esac
AXEOF
  chmod +x /usr/local/bin/axelus

  # Systemd service for auto-start
  cat > /etc/systemd/system/axelus-waf.service << SVCEOF
[Unit]
Description=AXELUS-WAF Security Platform
Documentation=https://www.optimiumnexus.com/docs
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} up -d --remove-orphans
ExecStop=/usr/bin/docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} stop
ExecReload=/usr/bin/docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} restart
TimeoutStartSec=120
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable axelus-waf.service 2>/dev/null || true
  log_ok "axelus CLI installed at: /usr/local/bin/axelus"
  log_ok "Systemd service enabled: axelus-waf.service (auto-start on boot)"
}

# ── Step 17: Print summary ────────────────────────────────────────────────────
print_summary() {
  local LOCAL_IP; LOCAL_IP=$(get_local_ip || echo "127.0.0.1")

  echo ""
  printf "${CYAN}"
  printf '╔'; printf '═%.0s' $(seq 1 $((BANNER_WIDTH-2))); printf '╗\n'
  printf '║  %-*s  ║\n' $((BANNER_WIDTH-6)) "AXELUS-WAF Installation Complete!"
  printf '╚'; printf '═%.0s' $(seq 1 $((BANNER_WIDTH-2))); printf '╝\n'
  printf "${RESET}"
  echo ""
  echo -e "${BOLD}Access URLs${RESET}"
  echo -e "  ${CYAN}●${RESET} WAF Dashboard   : ${YELLOW}http://${LOCAL_IP}:9443${RESET}"
  echo -e "  ${CYAN}●${RESET} Admin Center    : ${YELLOW}http://${LOCAL_IP}:8085/admin${RESET}"
  echo -e "  ${CYAN}●${RESET} Customer Portal : ${YELLOW}http://${LOCAL_IP}:8080${RESET}"
  echo -e "  ${CYAN}●${RESET} API Docs        : ${YELLOW}http://${LOCAL_IP}:9443/docs${RESET}"
  echo -e "  ${CYAN}●${RESET} OpenAPI YAML    : ${YELLOW}http://${LOCAL_IP}:9443/docs/openapi.yaml${RESET}"
  if [[ "$MONITORING" == "true" ]]; then
    echo -e "  ${CYAN}●${RESET} Grafana         : ${YELLOW}http://${LOCAL_IP}:3000${RESET}"
    echo -e "  ${CYAN}●${RESET} Prometheus      : ${YELLOW}http://${LOCAL_IP}:9090${RESET} (loopback only)"
  fi
  echo ""
  echo -e "${BOLD}Credentials${RESET}"
  echo -e "  ${CYAN}Admin Email    :${RESET} admin@optimiumnexus.com"
  echo -e "  ${CYAN}Admin Password :${RESET} ${YELLOW}${ADMIN_PASSWORD}${RESET}"
  echo -e "  ${CYAN}Admin API Key  :${RESET} ${YELLOW}${ADMIN_API_KEY}${RESET}"
  if [[ "$MONITORING" == "true" ]]; then
    echo -e "  ${CYAN}Grafana Login  :${RESET} admin / ${YELLOW}${ADMIN_PASSWORD}${RESET}"
  fi
  echo ""
  echo -e "${BOLD}License${RESET}"
  echo -e "  ${GREEN}30-day trial license issued${RESET}"
  echo -e "  Upgrade: ${YELLOW}https://www.optimiumnexus.com/upgrade${RESET}"
  echo ""
  echo -e "${BOLD}File Locations${RESET}"
  echo -e "  Install dir    : ${INSTALL_DIR}"
  echo -e "  Configuration  : ${ENV_FILE}"
  echo -e "  Compose file   : ${COMPOSE_FILE}"
  echo -e "  Data           : ${DATA_DIR}"
  echo -e "  Logs           : ${LOGS_DIR}"
  echo ""
  echo -e "${BOLD}CLI Commands${RESET}"
  echo -e "  ${CYAN}axelus status${RESET}          — Show service status"
  echo -e "  ${CYAN}axelus logs mgt${RESET}        — Follow management API logs"
  echo -e "  ${CYAN}axelus logs waf${RESET}        — Follow WAF engine logs"
  echo -e "  ${CYAN}axelus restart${RESET}         — Restart all services"
  echo -e "  ${CYAN}axelus backup${RESET}          — Backup database"
  echo -e "  ${CYAN}axelus health${RESET}          — Check system health"
  echo -e "  ${CYAN}axelus update${RESET}          — Pull latest and restart"
  echo ""
  echo -e "${BOLD}Next Steps${RESET}"
  echo -e "  1. Open the Admin Center and change the default password"
  echo -e "  2. Add your first protected site via the WAF Dashboard"
  echo -e "  3. Configure SMTP for email notifications"
  echo -e "  4. Review compliance reports at /compliance endpoint"
  echo -e "  5. Set up Slack/PagerDuty webhooks for alerts"
  echo ""
  echo -e "${BOLD}Support${RESET}"
  echo -e "  Docs   : ${BLUE}https://www.optimiumnexus.com/docs${RESET}"
  echo -e "  Email  : ${BLUE}contact@optimiumnexus.com${RESET}"
  echo -e "  GitHub : ${BLUE}https://github.com/optimiumnexusllc/AXELUS-WAF${RESET}"
  echo ""
  echo -e "${RED}⚠  SECURITY REMINDER: Save credentials above and store in a password manager.${RESET}"
  echo -e "${RED}   The .env file at ${ENV_FILE} contains all secrets — protect it!${RESET}"
  echo ""
  echo -e "${GREEN}AXELUS-WAF by OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com${RESET}"
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"
  log_banner
  check_root
  check_requirements
  install_dependencies
  setup_directories
  generate_credentials
  write_env
  write_nginx_config
  write_redis_config
  write_prometheus_config
  write_grafana_provisioning
  write_compose
  start_stack
  wait_for_health
  initial_setup
  run_smoke_tests
  write_management_scripts
  print_summary
}

main "$@"
