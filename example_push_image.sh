#!/bin/bash
set -euo pipefail

IMAGE="devops.laobullionbank.com/piti/ticket-app/backend"
VERSION="${1:-latest}"

echo "🚀 Building image: $IMAGE:$VERSION"

docker build --platform linux/amd64 -t "$IMAGE:$VERSION" .
docker push "$IMAGE:$VERSION"

echo "✅ Successfully pushed $IMAGE:$VERSION"
