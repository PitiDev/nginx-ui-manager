#!/bin/bash
set -euo pipefail

# ─── Configure ────────────────────────────────────────────────────────────────
DOCKERHUB_USER="pitidev"
IMAGE_NAME="nginx-ui-manager"
IMAGE="${DOCKERHUB_USER}/${IMAGE_NAME}"
VERSION="${1:-latest}"
# ──────────────────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}✓${NC}  $1"; }
info() { echo -e "${CYAN}→${NC}  $1"; }
err()  { echo -e "${RED}✗${NC}  $1"; exit 1; }

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Nginx UI — Push to Docker Hub${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Image  : ${IMAGE}:${VERSION}"
echo ""

# ── Step 1: Check docker login ────────────────────────────────────────────────
info "Checking Docker Hub login..."
if ! docker info 2>/dev/null | grep -q "Username"; then
    info "Not logged in. Running docker login..."
    docker login || err "Docker Hub login failed."
fi
log "Docker authenticated"

# ── Step 2: Build linux/amd64 ─────────────────────────────────────────────────
info "Building image for linux/amd64..."
docker build --platform linux/amd64 -t "${IMAGE}:${VERSION}" .
log "Built: ${IMAGE}:${VERSION}"

# ── Step 3: Also tag as latest if a specific version was given ────────────────
if [ "${VERSION}" != "latest" ]; then
    info "Tagging as latest..."
    docker tag "${IMAGE}:${VERSION}" "${IMAGE}:latest"
    log "Tagged: ${IMAGE}:latest"
fi

# ── Step 4: Push to Docker Hub ────────────────────────────────────────────────
info "Pushing ${IMAGE}:${VERSION} to Docker Hub..."
docker push "${IMAGE}:${VERSION}"
log "Pushed: ${IMAGE}:${VERSION}"

if [ "${VERSION}" != "latest" ]; then
    info "Pushing ${IMAGE}:latest..."
    docker push "${IMAGE}:latest"
    log "Pushed: ${IMAGE}:latest"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Done! Image available at:${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  https://hub.docker.com/r/${DOCKERHUB_USER}/${IMAGE_NAME}"
echo -e "  docker pull ${IMAGE}:${VERSION}"
echo ""
