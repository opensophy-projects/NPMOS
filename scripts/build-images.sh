#!/usr/bin/env bash
# Builds the NginxionS images locally:
#   nginxions, nginxions-openappsec (the agent, its shared storage and tuning services, nginxions-control)
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
[ ${#images[@]} -eq 0 ] && images=(nginxions openappsec)

for image in "${images[@]}"; do
  if [ "$image" = nginxions ]; then name=nginxions; else name="nginxions-$image"; fi
  echo "==> $REGISTRY/$name:$TAG"
  case "$image" in
    nginxions)
      docker build --build-arg "CROWDSEC_VERSION=$CROWDSEC_VERSION" \
        --build-arg "FLAGS=${FLAGS:--march=x86-64-v2 -mtune=generic -fcf-protection=full}" \
        -t "$REGISTRY/nginxions:$TAG" nginxions ;;
    openappsec)
      docker buildx build --load --build-context control=nginxions/backend/nginxions/control \
        --build-arg "OPENAPPSEC_REF=$OPENAPPSEC_REF" --build-arg "SHARED_FILES_REF=$SHARED_FILES_REF" \
        --build-arg "TUNING_REF=$TUNING_REF" -t "$REGISTRY/nginxions-openappsec:$TAG" deploy/openappsec ;;
    *) echo "unknown image: $image" >&2; exit 1 ;;
  esac
done
