#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  AXELUS-WAF — POC Setup Script                                             ║
# ║  Génère le .env, crée l'arborescence, lance le stack en 2 minutes          ║
# ║  Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
# Usage:
#   git clone https://github.com/optimiumnexusllc/AXELUS-WAF.git
#   cd AXELUS-WAF
#   sudo bash install/setup-poc.sh
#
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
OK="${GREEN}✓${RESET}"; ERR="${RED}✗${RESET}"; INFO="${CYAN}ℹ${RESET}"

# ── Config ────────────────────────────────────────────────────────────────────
SAFELINE_DIR="${SAFELINE_DIR:-/data/axelus-waf}"
SUBNET_PREFIX="${SUBNET_PREFIX:-172.22.222}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$REPO_DIR/docker-compose.poc.yml"

log() { echo -e "${INFO}  $*"; }
ok()  { echo -e "${OK}  $*"; }
err() { echo -e "${ERR}  $*" >&2; exit 1; }
# ── Progress tracking ─────────────────────────────────────────────────────────
TOTAL_STEPS=9
CURRENT_STEP=0
INSTALL_START=$(date +%s)

get_step_name() {
  case $1 in
    1) echo "Verification Docker" ;;
    2) echo "Verification compose" ;;
    3) echo "Creation repertoires" ;;
    4) echo "Generation secrets" ;;
    5) echo "Config monitoring" ;;
    6) echo "Pull images Docker" ;;
    7) echo "Demarrage stack" ;;
    8) echo "Smoke tests" ;;
    9) echo "Installation CLI" ;;
    *) echo "" ;;
  esac
}

_step_start_time=0
_dur_1=0; _dur_2=0; _dur_3=0; _dur_4=0; _dur_5=0
_dur_6=0; _dur_7=0; _dur_8=0; _dur_9=0

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

  printf "\n${CYAN}  ┌──────────────────────────────────────────────────────────────┐${RESET}\n"
  printf "${CYAN}  │${RESET}  "
  printf "${GREEN}"
  printf "%${filled}s" | tr " " "█"
  printf "${RESET}"
  printf "%${empty}s" | tr " " "░"
  printf " ${BOLD}%3d%%${RESET}  ⏱ %s" $pct "$elapsed_fmt"
  printf "%*s" $(( 10 - ${#elapsed_fmt} )) ""
  printf "${CYAN}│${RESET}\n"
  printf "${CYAN}  └──────────────────────────────────────────────────────────────┘${RESET}\n\n"

  for i in $(seq 1 $TOTAL_STEPS); do
    local name; name=$(get_step_name $i)
    if (( i < cur )); then
      printf "  ${GREEN}✓${RESET}  %d/%d  %-34s ${GREEN}%ss${RESET}\n" \
        $i $TOTAL_STEPS "$name" "$(eval echo \$_dur_$i)"
    elif (( i == cur )); then
      printf "  ${YELLOW}▶${RESET}  %d/%d  ${BOLD}%-34s${RESET} ${YELLOW}en cours...${RESET}\n" \
        $i $TOTAL_STEPS "$name"
    else
      printf "  ○  %d/%d  %-34s\n" $i $TOTAL_STEPS "$name"
    fi
  done
  echo ""
}

step() {
  if (( CURRENT_STEP > 0 )); then
    eval "_dur_${CURRENT_STEP}=$(( $(date +%s) - _step_start_time ))"
  fi
  CURRENT_STEP=$(( CURRENT_STEP + 1 ))
  _step_start_time=$(date +%s)
  clear 2>/dev/null || printf '\n%.0s' {1..3}
  printf "${CYAN}  ╔══════════════════════════════════════════════════════════════╗${RESET}\n"
  printf "${CYAN}  ║  ${BOLD}AXELUS-WAF POC Setup${RESET}${CYAN}  —  Étape %d/%d  —  %-20s║${RESET}\n" \
    $CURRENT_STEP $TOTAL_STEPS "$(get_step_name $CURRENT_STEP)"
  printf "${CYAN}  ╚══════════════════════════════════════════════════════════════╝${RESET}\n"
  draw_progress
}

gen_pass()   { openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 28; }
gen_secret() { openssl rand -hex 32; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || err "Run as root: sudo bash install/setup-poc.sh"

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  AXELUS-WAF POC Setup — OPTIMIUM NEXUS LLC          ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

# ── Step 1: Docker check ──────────────────────────────────────────────────────
step
command -v docker &>/dev/null || err "Docker not found. Install it first: curl -fsSL https://get.docker.com | bash"
docker compose version &>/dev/null || err "Docker Compose plugin not found. Install docker-compose-plugin."
ok "Docker $(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
ok "Docker Compose $(docker compose version --short)"
docker info &>/dev/null || { systemctl start docker; sleep 2; }

# ── Step 2: Check compose file ────────────────────────────────────────────────
step
[[ -f "$COMPOSE_FILE" ]] || err "docker-compose.poc.yml not found at: $COMPOSE_FILE"
ok "Compose file: $COMPOSE_FILE"

# ── Step 3: Create data directories ───────────────────────────────────────────
step
dirs=(
  "$SAFELINE_DIR/resources/"{postgres,mgt,detector,nginx,sock,chaos}
  "$SAFELINE_DIR/logs/nginx"
  "$REPO_DIR/monitoring/"{prometheus,alertmanager,grafana/provisioning/{datasources,dashboards}}
)
for d in "${dirs[@]}"; do
  mkdir -p "$d"
done
ok "Data directory: $SAFELINE_DIR"
ok "Config directory: $REPO_DIR/monitoring"

# ── Step 4: Generate .env ─────────────────────────────────────────────────────
step

POSTGRES_PASS=$(gen_pass)
REDIS_PASS=$(gen_pass)
JWT_SECRET=$(gen_secret)
ADMIN_KEY=$(gen_secret)
LICENSE_KEY=$(gen_secret)

ENV_FILE="$REPO_DIR/.env"
cat > "$ENV_FILE" << ENVEOF
# AXELUS-WAF — Auto-generated .env
# Generated: $(date -u "+%Y-%m-%d %H:%M UTC")
# DO NOT COMMIT THIS FILE

IMAGE_PREFIX=optimiumnexusllc
IMAGE_TAG=latest
ARCH_SUFFIX=
REGION=
RELEASE=
SUBNET_PREFIX=${SUBNET_PREFIX}
SAFELINE_DIR=${SAFELINE_DIR}
MGT_PORT=9443

POSTGRES_PASSWORD=${POSTGRES_PASS}
REDIS_PASSWORD=${REDIS_PASS}
JWT_SECRET=${JWT_SECRET}
ADMIN_API_KEY=${ADMIN_KEY}
LICENSE_ADMIN_KEY=${LICENSE_KEY}

TLS_ENABLED=false
MONITORING_ENABLED=true

# Optionnels — décommenter et remplir si besoin
# STRIPE_SECRET_KEY=
# SMTP_HOST=
# SMTP_PORT=587
# SMTP_USER=
# SMTP_PASSWORD=
# SLACK_WEBHOOK_URL=
# MAXMIND_LICENSE_KEY=
ENVEOF
chmod 640 "$ENV_FILE"
ok "Credentials generated → $ENV_FILE"

# ── Step 5: Write Prometheus config ───────────────────────────────────────────
step

cat > "$REPO_DIR/monitoring/prometheus/prometheus.yaml" << 'PROMEOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'axelus-mgt'
    static_configs:
      - targets: ['axelus-mgt:9443']
    metrics_path: '/api/open/health'
    scrape_timeout: 10s

  - job_name: 'postgres'
    static_configs:
      - targets: ['axelus-pg-exporter:9187']

  - job_name: 'nginx'
    static_configs:
      - targets: ['axelus-nginx-exporter:9113']
PROMEOF

cat > "$REPO_DIR/monitoring/alertmanager/alertmanager.yaml" << 'AMEOF'
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'default'

receivers:
  - name: 'default'
    # Configure Slack/PagerDuty/email here after install
AMEOF

# Grafana datasource provisioning
cat > "$REPO_DIR/monitoring/grafana/provisioning/datasources/prometheus.yaml" << 'DSEOF'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://axelus-prometheus:9090
    isDefault: true
    editable: false
DSEOF

cat > "$REPO_DIR/monitoring/grafana/provisioning/dashboards/dashboards.yaml" << 'DBEOF'
apiVersion: 1
providers:
  - name: AXELUS-WAF
    folder: AXELUS-WAF
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards
DBEOF
ok "Prometheus config written"
ok "Grafana provisioning written"
ok "AlertManager config written"

# ── Step 6: Pull images ───────────────────────────────────────────────────────
step
echo ""

images=(
  "optimiumnexusllc/axelus-postgres:15.2"
  "optimiumnexusllc/axelus-mgt:latest"
  "optimiumnexusllc/axelus-tengine:latest"
  "optimiumnexusllc/axelus-detector:latest"
  "optimiumnexusllc/axelus-fvm:latest"
  "optimiumnexusllc/axelus-luigi:latest"
  "optimiumnexusllc/axelus-chaos:latest"
  "redis:7.2-alpine"
  "prom/prometheus:v2.50.1"
  "grafana/grafana:10.4.0"
  "prom/alertmanager:v0.27.0"
  "prometheuscommunity/postgres-exporter:v0.15.0"
  "nginx/nginx-prometheus-exporter:1.1.0"
)

for img in "${images[@]}"; do
  printf "  Pulling %-52s" "$img"
  if docker pull --quiet "$img" &>/dev/null; then
    echo -e "${OK}"
  else
    echo -e "${YELLOW}⚠ skipped${RESET}"
  fi
done

# ── Step 7: Start the stack ───────────────────────────────────────────────────
step
cd "$REPO_DIR"

docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" \
  up -d --remove-orphans 2>&1 | \
  grep -E "Started|Created|Running|Error" || true

echo ""
log "Waiting for services to be ready..."

# Wait for Postgres
printf "  PostgreSQL  "
for i in $(seq 1 30); do
  docker exec axelus-pg pg_isready -U axelus -q 2>/dev/null && { echo -e "${OK}"; break; }
  sleep 2; printf "."; [[ $i -eq 30 ]] && echo -e " ${RED}timeout${RESET}"
done

# Wait for Management API
printf "  Management  "
for i in $(seq 1 40); do
  curl -sf http://127.0.0.1:9443/api/open/health &>/dev/null && { echo -e "${OK}"; break; }
  sleep 3; printf "."; [[ $i -eq 40 ]] && echo -e " ${YELLOW}check logs${RESET}"
done

# Wait for Grafana
printf "  Grafana     "
for i in $(seq 1 20); do
  curl -sf http://127.0.0.1:3000/api/health &>/dev/null && { echo -e "${OK}"; break; }
  sleep 3; printf "."; [[ $i -eq 20 ]] && echo -e " ${YELLOW}still starting${RESET}"
done

# ── Step 8: Smoke test ────────────────────────────────────────────────────────
step
PASS_COUNT=0; WARN_COUNT=0

check() {
  local name="$1"; shift
  if eval "$@" &>/dev/null; then
    echo -e "  ${OK} $name"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo -e "  ${WARN} $name (may still be starting)"
    WARN_COUNT=$((WARN_COUNT+1))
  fi
}

check "PostgreSQL running"     "docker ps --filter name=axelus-pg --filter status=running -q | grep -q ."
check "Redis running"          "docker ps --filter name=axelus-redis --filter status=running -q | grep -q ."
check "WAF engine running"     "docker ps --filter name=axelus-waf --filter status=running -q | grep -q ."
check "Management API running" "docker ps --filter name=axelus-mgt --filter status=running -q | grep -q ."
check "Detector running"       "docker ps --filter name=axelus-detector --filter status=running -q | grep -q ."
check "Management API health"  "curl -sf http://127.0.0.1:9443/api/open/health"
check "Port 80 open"           "ss -tlnp | grep -q ':80 '"
check "Port 9443 open"         "ss -tlnp | grep -q ':9443 '"
check "Prometheus healthy"     "curl -sf http://127.0.0.1:9090/-/healthy"
check "Grafana healthy"        "curl -sf http://127.0.0.1:3000/api/health | grep -q ok"

# ── Install axelus CLI ────────────────────────────────────────────────────────
step
REPO_DIR_ESC="${REPO_DIR//\//\\/}"
ENV_FILE_ESC="${ENV_FILE//\//\\/}"
COMPOSE_FILE_ESC="${COMPOSE_FILE//\//\\/}"

cat > /usr/local/bin/axelus << CLIEOF
#!/usr/bin/env bash
# AXELUS-WAF management CLI
REPO_DIR="${REPO_DIR}"
COMPOSE_FILE="${COMPOSE_FILE}"
ENV_FILE="${ENV_FILE}"
cd "\$REPO_DIR"
set -a; source "\$ENV_FILE"; set +a
case "\${1:-help}" in
  start)    docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" up -d ;;
  stop)     docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" stop ;;
  restart)  docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" restart ;;
  status)   docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" ps ;;
  logs)     docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" logs -f "\${2:-}" ;;
  pull)     docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" pull ;;
  down)     docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" down ;;
  shell)    docker exec -it "axelus-\${2:-mgt}" /bin/sh ;;
  health)   curl -sf http://127.0.0.1:9443/api/open/health | python3 -m json.tool 2>/dev/null || echo "API not ready" ;;
  ps)       docker compose -f "\$COMPOSE_FILE" --env-file "\$ENV_FILE" ps ;;
  backup)
    TS=\$(date +%Y%m%d_%H%M%S)
    F="\$REPO_DIR/backup-\$TS.sql.gz"
    docker exec axelus-pg pg_dump -U axelus axelus | gzip > "\$F"
    echo "Backup saved: \$F"
    ;;
  *)
    echo "AXELUS-WAF CLI — OPTIMIUM NEXUS LLC"
    echo ""
    echo "Commands: start | stop | restart | status | logs [svc] | shell [svc]"
    echo "          pull | down | health | backup | ps"
    ;;
esac
CLIEOF
chmod +x /usr/local/bin/axelus
ok "axelus CLI installed"

# ── Systemd service ───────────────────────────────────────────────────────────
cat > /etc/systemd/system/axelus-waf.service << SVCEOF
[Unit]
Description=AXELUS-WAF Security Platform
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${REPO_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} up -d
ExecStop=/usr/bin/docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} stop
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
SVCEOF
systemctl daemon-reload
systemctl enable axelus-waf.service &>/dev/null || true
ok "Auto-start service enabled (systemd)"

# ── Summary ───────────────────────────────────────────────────────────────────
LOCAL_IP=$(ip route get 1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1 || echo "YOUR_SERVER_IP")

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  AXELUS-WAF Installation Complete!                              ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}Access URLs${RESET}"
echo -e "  ${CYAN}WAF Dashboard   :${RESET} ${YELLOW}http://${LOCAL_IP}:9443${RESET}"
echo -e "  ${CYAN}Grafana         :${RESET} ${YELLOW}http://${LOCAL_IP}:3000${RESET}"
echo -e "  ${CYAN}Prometheus      :${RESET} http://127.0.0.1:9090  (loopback only)"
echo ""
echo -e "${BOLD}Credentials${RESET}"
echo -e "  ${CYAN}Admin email     :${RESET} admin@optimiumnexus.com"
echo -e "  ${CYAN}Admin API Key   :${RESET} ${YELLOW}${ADMIN_KEY}${RESET}"
echo -e "  ${CYAN}PostgreSQL pass :${RESET} ${YELLOW}${POSTGRES_PASS}${RESET}"
echo -e "  ${CYAN}Grafana login   :${RESET} admin / ${YELLOW}${POSTGRES_PASS}${RESET}"
echo ""
echo -e "${BOLD}Saved in${RESET}: ${ENV_FILE}"
echo ""
echo -e "${BOLD}Commands${RESET}"
echo -e "  axelus status   — voir les conteneurs"
echo -e "  axelus logs mgt — logs de l'API"
echo -e "  axelus logs waf — logs du WAF"
echo -e "  axelus health   — santé de l'API"
echo -e "  axelus backup   — backup PostgreSQL"
echo ""
echo -e "  ${YELLOW}axelus status${RESET}"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | head -20
echo ""
# Final step complete
eval "_dur_${CURRENT_STEP}=$(( $(date +%s) - _step_start_time ))"
CURRENT_STEP=$TOTAL_STEPS
clear 2>/dev/null || true
printf "${CYAN}  ╔══════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${CYAN}  ║  ${BOLD}AXELUS-WAF POC${RESET}${CYAN}  —  Installation terminée !                  ║${RESET}\n"
printf "${CYAN}  ╚══════════════════════════════════════════════════════════════╝${RESET}\n"
draw_progress

echo -e "${GREEN}AXELUS-WAF — OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com${RESET}"
