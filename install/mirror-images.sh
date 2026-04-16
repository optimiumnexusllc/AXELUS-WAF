#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  AXELUS-WAF — Docker Image Mirroring Script                                ║
# ║  Pulls chaitin/safeline-* and pushes as optimiumnexusllc/axelus-*          ║
# ║  Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
# Usage:
#   export DOCKER_USERNAME=optimiumnexusllc
#   export DOCKER_PASSWORD=your-docker-hub-token
#   bash install/mirror-images.sh
#
# Or interactively:
#   bash install/mirror-images.sh --login
#
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
OK="${GREEN}✓${RESET}"; ERR="${RED}✗${RESET}"; WARN="${YELLOW}⚠${RESET}"

SRC_ORG="chaitin"
DST_ORG="optimiumnexusllc"

# ── Images to mirror ──────────────────────────────────────────────────────────
# Format: "source-name:tag:dest-name:dest-tag"
declare -a IMAGES=(
  "safeline-postgres:15.2:axelus-postgres:15.2"
  "safeline-postgres:15.2:axelus-postgres:latest"
  "safeline-mgt:latest:axelus-mgt:latest"
  "safeline-tengine:latest:axelus-tengine:latest"
  "safeline-detector:latest:axelus-detector:latest"
  "safeline-fvm:latest:axelus-fvm:latest"
  "safeline-luigi:latest:axelus-luigi:latest"
  "safeline-chaos:latest:axelus-chaos:latest"
)

# ── Parse args ────────────────────────────────────────────────────────────────
DO_LOGIN=false
DRY_RUN=false
PUSH=true

for arg in "$@"; do
  case "$arg" in
    --login)    DO_LOGIN=true ;;
    --dry-run)  DRY_RUN=true; PUSH=false ;;
    --no-push)  PUSH=false ;;
    --help|-h)
      echo "Usage: bash mirror-images.sh [--login] [--dry-run] [--no-push]"
      echo ""
      echo "  --login    Prompt for Docker Hub credentials"
      echo "  --dry-run  Only show what would be done (no pull/push)"
      echo "  --no-push  Pull and tag but don't push"
      echo ""
      echo "Environment variables:"
      echo "  DOCKER_USERNAME   Docker Hub username (default: optimiumnexusllc)"
      echo "  DOCKER_PASSWORD   Docker Hub password or access token"
      exit 0
      ;;
  esac
done

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  AXELUS-WAF Image Mirror — ${SRC_ORG}/safeline-* → ${DST_ORG}/axelus-*  ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

# ── Docker login ──────────────────────────────────────────────────────────────
if [[ "$DO_LOGIN" == true ]]; then
  echo -e "${BOLD}Docker Hub Login${RESET}"
  read -rp "  Username [optimiumnexusllc]: " DOCKER_USERNAME
  DOCKER_USERNAME="${DOCKER_USERNAME:-optimiumnexusllc}"
  read -rsp "  Password/Token: " DOCKER_PASSWORD
  echo ""
fi

DOCKER_USERNAME="${DOCKER_USERNAME:-optimiumnexusllc}"

if [[ -n "${DOCKER_PASSWORD:-}" ]]; then
  echo -e "  Logging in as ${DOCKER_USERNAME}..."
  echo "$DOCKER_PASSWORD" | docker login --username "$DOCKER_USERNAME" --password-stdin
  echo -e "${OK}  Logged in to Docker Hub"
else
  # Check if already logged in
  if ! docker system info 2>/dev/null | grep -q "Username"; then
    echo -e "${WARN}  Not logged in to Docker Hub. Run:"
    echo -e "       docker login --username optimiumnexusllc"
    echo -e "  Or:  bash $0 --login"
    echo -e "  Or set DOCKER_USERNAME + DOCKER_PASSWORD env vars"
    exit 1
  fi
  echo -e "${OK}  Using existing Docker Hub session"
fi

echo ""

# ── Mirror function ───────────────────────────────────────────────────────────
mirror_image() {
  local src_name="$1" src_tag="$2" dst_name="$3" dst_tag="$4"

  local src="${SRC_ORG}/${src_name}:${src_tag}"
  local dst="${DST_ORG}/${dst_name}:${dst_tag}"

  printf "  %-48s → %s\n" "$src" "$dst"

  if [[ "$DRY_RUN" == true ]]; then
    echo -e "     ${YELLOW}[dry-run] skipped${RESET}"
    return 0
  fi

  # Pull
  if ! docker pull --quiet "$src" 2>/dev/null; then
    echo -e "     ${ERR} Pull failed: ${src}"
    return 1
  fi

  # Inspect: get digest and labels
  local digest; digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$src" 2>/dev/null | cut -d@ -f2 || echo "")
  local created; created=$(docker inspect --format='{{.Created}}' "$src" 2>/dev/null | cut -c1-19 || echo "")

  # Re-tag with AXELUS labels
  docker tag "$src" "$dst"

  # Add AXELUS metadata as a new layer via dockerfile
  local tmp_dir; tmp_dir=$(mktemp -d)
  cat > "$tmp_dir/Dockerfile" << DOCKERFILE
FROM ${dst}
LABEL org.opencontainers.image.title="${dst_name}"
LABEL org.opencontainers.image.vendor="OPTIMIUM NEXUS LLC"
LABEL org.opencontainers.image.url="https://www.optimiumnexus.com"
LABEL org.opencontainers.image.source="https://github.com/optimiumnexusllc/AXELUS-WAF"
LABEL org.opencontainers.image.version="${dst_tag}"
LABEL com.axelus.base-image="${src}"
LABEL com.axelus.base-digest="${digest}"
LABEL com.axelus.mirrored-at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DOCKERFILE

  docker build --quiet -t "$dst" "$tmp_dir" 2>/dev/null
  rm -rf "$tmp_dir"

  # Push
  if [[ "$PUSH" == true ]]; then
    if docker push --quiet "$dst" 2>/dev/null; then
      echo -e "     ${OK} pushed"
    else
      echo -e "     ${ERR} push failed — check Docker Hub permissions for ${DST_ORG}"
      return 1
    fi
  else
    echo -e "     ${WARN} tagged (push skipped)"
  fi
}

# ── Main mirror loop ──────────────────────────────────────────────────────────
echo -e "${BOLD}Mirroring images${RESET}"
echo -e "  Source  : Docker Hub / ${SRC_ORG}"
echo -e "  Target  : Docker Hub / ${DST_ORG}"
echo -e "  Images  : ${#IMAGES[@]}"
if [[ "$DRY_RUN" == true ]]; then echo -e "  Mode    : DRY RUN (no pull/push)"; fi
echo ""

TOTAL=0; SUCCESS=0; FAILED=0

for entry in "${IMAGES[@]}"; do
  IFS=':' read -r src_name src_tag dst_name dst_tag <<< "$entry"
  ((TOTAL++))
  if mirror_image "$src_name" "$src_tag" "$dst_name" "$dst_tag"; then
    ((SUCCESS++))
  else
    ((FAILED++))
  fi
  echo ""
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}Summary${RESET}"
echo -e "  ${GREEN}${SUCCESS} succeeded${RESET} / ${RED}${FAILED} failed${RESET} / ${TOTAL} total"
echo ""

if [[ $SUCCESS -gt 0 && "$PUSH" == true ]]; then
  echo -e "${BOLD}Images available at:${RESET}"
  for entry in "${IMAGES[@]}"; do
    IFS=':' read -r src_name src_tag dst_name dst_tag <<< "$entry"
    echo -e "  ${CYAN}docker pull ${DST_ORG}/${dst_name}:${dst_tag}${RESET}"
  done
  echo ""
  echo -e "${BOLD}Next steps:${RESET}"
  echo -e "  1. Update docker-compose.poc.yml IMAGE_PREFIX to: ${DST_ORG}"
  echo -e "  2. The compose files now use your own images (no dependency on chaitin)"
  echo -e "  3. Schedule monthly mirror via GitHub Actions: .github/workflows/mirror-images.yml"
fi

echo ""
echo -e "${GREEN}Mirror complete — OPTIMIUM NEXUS LLC${RESET}"
