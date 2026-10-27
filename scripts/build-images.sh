#!/usr/bin/env bash
# Builds the NPMOS images locally:
#   npmos, npmos-appsec-agent, npmos-appsec-smartsync, npmos-appsec-shared-storage, npmos-appsec-tuning
#
#   scripts/build-images.sh                    # all images, tag local/<name>:dev
#   scripts/build-images.sh npmos appsec-agent # selected images
#   REGISTRY=docker.io/opensophy TAG=test scripts/build-images.sh
#
# The npmos and appsec-agent images compile nginx / the agent from source: expect 30-60 min each
# on a first build (later builds use the Docker cache). The others take a few minutes.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=../deploy/openappsec/sources.env
. deploy/openappsec/sources.env
CROWDSEC_VERSION=$(sed -n 's/^CROWDSEC_VERSION=//p' deploy/.env)

REGISTRY="${REGISTRY:-local}"
TAG="${TAG:-dev}"
images=("$@")
[ ${#images[@]} -eq 0 ] && images=(npmos appsec-agent appsec-smartsync appsec-shared-storage appsec-tuning)

go_service() { # name repo ref
  docker build -f deploy/openappsec/go-service/Dockerfile \
    --build-arg "REPO=https://github.com/openappsec/$2.git" --build-arg "REF=$3" \
    -t "$REGISTRY/npmos-$1:$TAG" deploy/openappsec/go-service
}

for image in "${images[@]}"; do
  if [ "$image" = npmos ]; then name=npmos; else name="npmos-$image"; fi
  echo "==> $REGISTRY/$name:$TAG"
  case "$image" in
    npmos)
      docker build --build-arg "CROWDSEC_VERSION=$CROWDSEC_VERSION" \
        --build-arg "FLAGS=${FLAGS:--march=x86-64-v2 -mtune=generic -fcf-protection=full}" \
        -t "$REGISTRY/npmos:$TAG" npmos ;;
    appsec-agent)
      docker build --build-arg "OPENAPPSEC_REF=$OPENAPPSEC_REF" \
        -t "$REGISTRY/npmos-appsec-agent:$TAG" deploy/openappsec/agent ;;
    appsec-smartsync) go_service appsec-smartsync smartsync "$SMARTSYNC_REF" ;;
    appsec-shared-storage) go_service appsec-shared-storage smartsync-shared-files "$SHARED_FILES_REF" ;;
    appsec-tuning) go_service appsec-tuning smartsync-tuning "$TUNING_REF" ;;
    *) echo "unknown image: $image" >&2; exit 1 ;;
  esac
done
