#!/usr/bin/env bash
# Builds the NPMOS images locally:
#   npmos, npmos-openappsec (the agent, its shared storage and tuning services, npmos-control)
#
#   scripts/build-images.sh                    # all images, tag local/<name>:dev
#   scripts/build-images.sh openappsec         # selected images
#   REGISTRY=docker.io/opensophy TAG=test scripts/build-images.sh
#
# Both compile from source (nginx / the agent): expect 30-60 min each on a first build (later builds use the
# Docker cache).
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=../deploy/openappsec/sources.env
. deploy/openappsec/sources.env
CROWDSEC_VERSION=$(sed -n 's/^CROWDSEC_VERSION=//p' deploy/.env)

REGISTRY="${REGISTRY:-local}"
TAG="${TAG:-dev}"
images=("$@")
[ ${#images[@]} -eq 0 ] && images=(npmos openappsec)

for image in "${images[@]}"; do
  if [ "$image" = npmos ]; then name=npmos; else name="npmos-$image"; fi
  echo "==> $REGISTRY/$name:$TAG"
  case "$image" in
    npmos)
      docker build --build-arg "CROWDSEC_VERSION=$CROWDSEC_VERSION" \
        --build-arg "FLAGS=${FLAGS:--march=x86-64-v2 -mtune=generic -fcf-protection=full}" \
        -t "$REGISTRY/npmos:$TAG" npmos ;;
    openappsec)
      docker buildx build --load --build-context control=npmos/backend/npmos/control \
        --build-arg "OPENAPPSEC_REF=$OPENAPPSEC_REF" --build-arg "SHARED_FILES_REF=$SHARED_FILES_REF" \
        --build-arg "TUNING_REF=$TUNING_REF" -t "$REGISTRY/npmos-openappsec:$TAG" deploy/openappsec ;;
    *) echo "unknown image: $image" >&2; exit 1 ;;
  esac
done
