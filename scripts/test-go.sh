#!/usr/bin/env bash
# go vet and go test of the Go services of the agent (openappsec/), in the Go image of deploy/openappsec/Dockerfile
# (the same Go that builds them into nginxions-openappsec). smartsync is not in the image: it is vetted and tested too,
# so that its code stays buildable.
#
#   scripts/test-go.sh                       # vet and tests
#   COVERAGE_DIR=out scripts/test-go.sh      # also out/coverage-go-<service>.txt (go tool cover -func) for the report
#   CA_BUNDLE=/path/ca.crt scripts/test-go.sh   # behind a proxy with its own CA (HTTPS_PROXY is passed on)
set -euo pipefail
cd "$(dirname "$0")/.."

image=$(grep -o 'docker.io/library/golang:[^ ]*' deploy/openappsec/Dockerfile | head -1)
[ -n "$image" ] || { echo "no golang image in deploy/openappsec/Dockerfile"; exit 1; }
cover=""
if [ -n "${COVERAGE_DIR:-}" ]; then
  mkdir -p "$COVERAGE_DIR"
  cover=$(cd "$COVERAGE_DIR" && pwd)
fi

net=()
[ -z "${HTTPS_PROXY:-}" ] || net+=(--network host -e HTTPS_PROXY -e HTTP_PROXY -e NO_PROXY)
[ -z "${CA_BUNDLE:-}" ] || net+=(-v "$CA_BUNDLE:/etc/ssl/certs/ca-certificates.crt:ro")

for svc in smartsync-shared-files smartsync-tuning smartsync; do
  echo "==> $svc"
  docker run --rm "${net[@]}" -e GOTOOLCHAIN=local -e CGO_ENABLED=0 -e SVC="$svc" -e COVER="${cover:+/cover}" \
    -v "$PWD/openappsec/$svc:/app:ro" ${cover:+-v "$cover:/cover"} -w /app "$image" sh -ec '
      export GOFLAGS=-mod=readonly GOCACHE=/tmp/gocache
      # composites: struct literals of upstream without field names, a matter of style
      go vet -composites=false ./...
      if [ -n "$COVER" ]; then
        go test -coverprofile=/tmp/cover.out ./...
        go tool cover -func=/tmp/cover.out > "$COVER/coverage-go-$SVC.txt"
        tail -n 1 "$COVER/coverage-go-$SVC.txt"
      else
        go test ./...
      fi'
done
