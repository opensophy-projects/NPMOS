#!/usr/bin/env bash
# Closed-network test: brings up a fresh stack where no network can reach the internet,
# runs deploy/test/smoke.sh inside it and checks that no service tried to go online.
#
#   scripts/test-airgap.sh                 # full stack
#   SERVICES="npmos crowdsec" scripts/test-airgap.sh   # subset (dependencies are added by compose)
#
# Images come from NPMOS_IMAGE / NPMOS_CROWDSEC_IMAGE / NPMOS_VERSION (see deploy/compose.yaml).
set -euo pipefail

cd "$(dirname "$0")/.."

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-npmos-airgap}"
compose=(docker compose -f deploy/compose.yaml -f deploy/test/compose.airgap.yaml)
read -r -a services <<< "${SERVICES:-npmos appsec-agent appsec-smartsync appsec-shared-storage appsec-tuning-svc crowdsec socket-proxy}"

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    echo "--- logs (failure) ---"
    "${compose[@]}" logs --no-color --tail 80 || true
  fi
  [ "${KEEP:-}" = 1 ] || "${compose[@]}" down -v --remove-orphans > /dev/null 2>&1 || true
  exit $status
}
trap cleanup EXIT

"${compose[@]}" up -d --no-build "${services[@]}" test-upstream

echo "==> waiting for npmos to become healthy"
for i in $(seq 1 90); do
  state=$(docker inspect -f '{{.State.Health.Status}}' "$("${compose[@]}" ps -q npmos)" 2>/dev/null || true)
  [ "$state" = healthy ] && break
  [ "$i" = 90 ] && { echo "npmos is not healthy: $state"; exit 1; }
  sleep 2
done

"${compose[@]}" run --rm tester

echo "==> all requested services are still running"
for s in "${services[@]}"; do
  id=$("${compose[@]}" ps -q "$s")
  [ -n "$id" ] && [ "$(docker inspect -f '{{.State.Running}}' "$id")" = true ] || { echo "FAIL: $s is not running"; exit 1; }
done

if [[ " ${services[*]} " == *" crowdsec "* ]]; then
  echo "==> CrowdSec runs locally with the NPMOS bouncer pre-registered"
  "${compose[@]}" exec -T crowdsec cscli bouncers list -o raw | grep -q '^npmos,' || { echo "FAIL: bouncer npmos is not registered"; exit 1; }
fi

echo "==> no phone-home attempts in logs"
# Messages that only appear when a component tries to reach a cloud service by default
if "${compose[@]}" logs --no-color "${services[@]}" 2>&1 \
  | grep -E "Fetching IP Ranges|Error downloading gravatar|Failed to fetch remote version|api\.crowdsec\.net|my\.openappsec\.io"; then
  echo "FAIL: a component tried to reach a cloud service"
  exit 1
fi

echo "OK: closed-network test passed"
