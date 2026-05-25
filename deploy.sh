#!/bin/bash
set -euo pipefail

# ─── Configure ────────────────────────────────────────────────────────────────
REGISTRY="devops.laobullionbank.com"
IMAGE_PATH="piti/nginx-ui"
IMAGE="${REGISTRY}/${IMAGE_PATH}"
VERSION="${1:-latest}"

SERVER_HOST="172.16.0.49"
SERVER_USER="lbb_admin"
SERVER_PORT=99
SERVER_DIR="/home/${SERVER_USER}/nginx_ui"
SSH_KEY=""              # path to .pem or id_rsa, leave empty when using sshpass
# ──────────────────────────────────────────────────────────────────────────────

# ── SSH password (sshpass) ────────────────────────────────────────────────────
# Set SSH_PASSWORD in your environment or export it before running:
#   export SSH_PASSWORD=yourpassword && sh deploy.sh
# Never hardcode it here.
SSH_PASSWORD="${SSH_PASSWORD:-}"

if [ -n "$SSH_PASSWORD" ]; then
    if ! command -v sshpass &>/dev/null; then
        echo "sshpass not found. Install it first:"
        echo "  macOS:  brew install hudochenkov/sshpass/sshpass"
        echo "  Ubuntu: sudo apt-get install sshpass"
        exit 1
    fi
    SSHPASS_PREFIX="sshpass -e"
    export SSHPASS="$SSH_PASSWORD"
else
    SSHPASS_PREFIX=""
fi

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}✓${NC}  $1"; }
info() { echo -e "${CYAN}→${NC}  $1"; }
warn() { echo -e "${YELLOW}!${NC}  $1"; }
err()  { echo -e "${RED}✗${NC}  $1"; exit 1; }

# ── SSH options ───────────────────────────────────────────────────────────────
SSH_OPTS="-p ${SERVER_PORT} -o StrictHostKeyChecking=no -o ConnectTimeout=10"
[ -n "$SSH_KEY" ] && SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
SSH="${SSHPASS_PREFIX} ssh $SSH_OPTS ${SERVER_USER}@${SERVER_HOST}"
SCP="${SSHPASS_PREFIX} scp -P ${SERVER_PORT} -o StrictHostKeyChecking=no"
[ -n "$SSH_KEY" ] && SCP="$SCP -i $SSH_KEY"

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Nginx UI — Deploy Script${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Image  : ${IMAGE}:${VERSION}"
echo -e "  Server : ${SERVER_USER}@${SERVER_HOST}:${SERVER_PORT}"
echo -e "  Dir    : ${SERVER_DIR}"
echo ""

# ── Step 1: Build ─────────────────────────────────────────────────────────────
info "Building image for linux/amd64..."
docker build --platform linux/amd64 -t "${IMAGE}:${VERSION}" .
log "Built: ${IMAGE}:${VERSION}"

# ── Step 2: Push to registry ──────────────────────────────────────────────────
info "Pushing to registry ${REGISTRY}..."
docker push "${IMAGE}:${VERSION}"
log "Pushed: ${IMAGE}:${VERSION}"

# ── Step 3: Prepare remote directory & files ──────────────────────────────────
info "Preparing remote directories..."
$SSH "mkdir -p ${SERVER_DIR} ${SERVER_DIR}/data" || err "Cannot connect to server."
# Fix ownership in case prior deploy ran as root
printf '%s\n' "${SSH_PASSWORD}" | $SSH -T "sudo -S chown -R ${SERVER_USER}:${SERVER_USER} ${SERVER_DIR} 2>/dev/null; true"
log "Remote directories ready"

info "Uploading docker-compose.yml..."
$SCP "docker-compose.yml" "${SERVER_USER}@${SERVER_HOST}:${SERVER_DIR}/"
log "docker-compose.yml uploaded"

if [ -f ".env" ]; then
    info "Uploading .env..."
    $SCP ".env" "${SERVER_USER}@${SERVER_HOST}:${SERVER_DIR}/"
    log ".env uploaded"
else
    warn ".env not found locally — make sure it exists on the server"
fi

# ── Step 4: Pull & restart on server ─────────────────────────────────────────
info "Pulling image and restarting on server..."
# SSH_PASSWORD is expanded locally; all traffic is SSH-encrypted in transit.
$SSH bash -s << REMOTE
    set -e
    SPWD='${SSH_PASSWORD}'
    cd ${SERVER_DIR}

    echo "  Pulling image..."
    echo "\$SPWD" | sudo -S docker pull ${IMAGE}:${VERSION}

    echo "  Restarting container..."
    echo "\$SPWD" | sudo -S docker compose down 2>/dev/null || true
    echo "\$SPWD" | sudo -S docker compose up -d

    echo ""
    echo "  Container status:"
    echo "\$SPWD" | sudo -S docker compose ps
REMOTE

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Deploy complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  URL : http://${SERVER_HOST}:8080"
echo ""
