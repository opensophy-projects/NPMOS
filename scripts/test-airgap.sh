#!/usr/bin/env bash
# Closed-network test: brings up a fresh stack where no network can reach the internet,
# runs deploy/test/smoke.sh inside it and checks that no service tried to go online.
#
#   scripts/test-airgap.sh                 # full stack
#   SERVICES="npmos crowdsec" scripts/test-airgap.sh   # subset (dependencies are added by compose)
#
# Images: NPMOS_REGISTRY / NPMOS_VERSION and the pinned versions in deploy/.env.
set -euo pipefail

cd "$(dirname "$0")/.."

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-npmos-airgap}"
compose=(docker compose -f deploy/compose.yaml -f deploy/test/compose.airgap.yaml)
read -r -a services <<< "${SERVICES:-npmos appsec-agent appsec-smartsync appsec-shared-storage appsec-tuning-svc crowdsec socket-proxy npmos-control}"

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


wait_healthy() {
  for i in $(seq 1 90); do
    state=$(docker inspect -f '{{.State.Health.Status}}' "$("${compose[@]}" ps -q npmos)" 2>/dev/null || true)
    [ "$state" = healthy ] && return 0
    [ "$i" = 90 ] && { echo "npmos is not healthy: $state"; return 1; }
    sleep 2
  done
}

echo "==> waiting for npmos to become healthy"
wait_healthy
"${compose[@]}" run --rm -T tester

echo "==> restart npmos"
"${compose[@]}" restart npmos
wait_healthy
"${compose[@]}" run --rm -T tester after-restart

echo "==> all requested services are still running"
for s in "${services[@]}"; do
  id=$("${compose[@]}" ps -q "$s")
  [ -n "$id" ] && [ "$(docker inspect -f '{{.State.Running}}' "$id")" = true ] || { echo "FAIL: $s is not running"; exit 1; }
done

if [[ " ${services[*]} " == *" crowdsec "* ]]; then
  echo "==> CrowdSec runs locally with the NPMOS bouncer pre-registered"
  "${compose[@]}" exec -T crowdsec cscli bouncers list -o raw | grep -q '^npmos,' || { echo "FAIL: bouncer npmos is not registered"; exit 1; }
  "${compose[@]}" exec -T crowdsec cscli bouncers list -o raw | grep -q '^appsec,' || { echo "FAIL: bouncer appsec is not registered"; exit 1; }
  if [[ " ${services[*]} " == *" appsec-agent "* ]]; then
    # smoke switched on "IP reputation from CrowdSec" in WAF -> Agent: the agent polls the local LAPI
    echo "==> the open-appsec agent pulls CrowdSec decisions from the local LAPI"
    for i in $(seq 1 30); do
      line=$("${compose[@]}" exec -T crowdsec cscli bouncers list -o raw | grep '^appsec,' || true)
      # name,ip,valid,last_pull,...: last_pull is set after the first pull
      [ -n "$(echo "$line" | cut -d, -f4)" ] && break
      [ "$i" = 30 ] && { echo "FAIL: the agent never pulled CrowdSec decisions: $line"; exit 1; }
      sleep 2
    done
  fi
fi

echo "==> no phone-home attempts in logs"
# Messages that only appear when a component tries to reach a cloud service by default
if "${compose[@]}" logs --no-color "${services[@]}" 2>&1 \
  | grep -E "Fetching IP Ranges|Error downloading gravatar|Failed to fetch remote version|Registering ACME account|certbot.ini register|api\.crowdsec\.net|version\.crowdsec\.net|my\.openappsec\.io|cloud\.ngen\.checkpoint\.com"; then
  echo "FAIL: a component tried to reach a cloud service"
  exit 1
fi

echo "OK: closed-network test passed"
