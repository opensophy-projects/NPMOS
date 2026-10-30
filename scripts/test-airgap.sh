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
read -r -a services <<< "${SERVICES:-npmos appsec-agent appsec-shared-storage appsec-tuning-svc crowdsec socket-proxy npmos-control}"

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    echo "--- logs (failure) ---"
    "${compose[@]}" logs --no-color --tail 80 || true
    if [ -n "$("${compose[@]}" ps -q appsec-agent 2> /dev/null)" ]; then
      echo "--- open-appsec agent: log files, settings, policy status (failure) ---"
      "${compose[@]}" exec -T appsec-agent sh -c 'ls -la /var/log/nano_agent; cat /etc/cp/conf/settings.json;
        cat /ext/appsec/npmos-agent.env; tail -n 5 /var/log/nano_agent/cp-nano-http-transaction-handler.log*;
        tail -n 20 /var/log/nano_agent/*.err 2> /dev/null' || true
    fi
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
  echo "==> NPMOS manages CrowdSec: its machine is registered, the hub index comes from NPMOS"
  "${compose[@]}" exec -T crowdsec cscli machines list -o raw | grep -q '^npmos-' || { echo "FAIL: the machine of NPMOS is not registered"; exit 1; }
  "${compose[@]}" exec -T crowdsec cscli hub update > /dev/null || { echo "FAIL: cscli hub update does not reach the hub of NPMOS"; exit 1; }
  # smoke banned the tester through the bouncer of NPMOS in nginx: it reads the decisions of the local LAPI
  echo "==> the CrowdSec bouncer of NPMOS pulls decisions from the local LAPI"
  line=$("${compose[@]}" exec -T crowdsec cscli bouncers list -o raw | grep '^npmos,' || true)
  # name,ip,valid,last_pull,...: last_pull is set after the first pull
  [ -n "$(echo "$line" | cut -d, -f4)" ] || { echo "FAIL: the bouncer of NPMOS never pulled CrowdSec decisions: $line"; exit 1; }
  # the IP reputation of the agent stays off (WAF -> Agent): it would hold every request for a lookup
fi

echo "==> no phone-home attempts in logs"
# Messages that only appear when a component tries to reach a cloud service by default
if "${compose[@]}" logs --no-color "${services[@]}" 2>&1 \
  | grep -E "Fetching IP Ranges|Error downloading gravatar|Failed to fetch remote version|Registering ACME account|certbot.ini register|api\.crowdsec\.net|version\.crowdsec\.net|my\.openappsec\.io|cloud\.ngen\.checkpoint\.com"; then
  echo "FAIL: a component tried to reach a cloud service"
  exit 1
fi

echo "OK: closed-network test passed"
