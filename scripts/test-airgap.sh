#!/usr/bin/env bash
# Closed-network test: brings up a fresh stack where no network can reach the internet,
# runs deploy/test/smoke.sh inside it and checks that no service tried to go online.
#
#   scripts/test-airgap.sh                 # full stack
#   SERVICES="nginxions crowdsec" scripts/test-airgap.sh   # subset (dependencies are added by compose)
#
# Images: NGINXIONS_REGISTRY / NGINXIONS_VERSION and the pinned versions in deploy/.env.
set -euo pipefail

cd "$(dirname "$0")/.."

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-nginxions-airgap}"
compose=(docker compose -f deploy/compose.yaml -f deploy/test/compose.airgap.yaml)
read -r -a services <<< "${SERVICES:-nginxions openappsec crowdsec}"

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    echo "--- logs (failure) ---"
    "${compose[@]}" logs --no-color --tail 80 || true
    if [ -n "$("${compose[@]}" ps -q openappsec 2> /dev/null)" ]; then
      echo "--- open-appsec agent: log files, settings, policy status (failure) ---"
      "${compose[@]}" exec -T openappsec sh -c 'ls -la /var/log/nano_agent; cat /etc/cp/conf/settings.json;
        cat /ext/appsec/nginxions-agent.env; tail -n 5 /var/log/nano_agent/cp-nano-http-transaction-handler.log*;
        tail -n 20 /var/log/nano_agent/*.err 2> /dev/null;
        echo "--- orchestration: checks of updates, policies applied ---";
        grep -h "check update\|Check update\|NginxionS\|apply\|Failed" /var/log/nano_agent/cp-nano-orchestration.dbg* \
          2> /dev/null | tail -n 40' || true
    fi
  fi
  [ "${KEEP:-}" = 1 ] || "${compose[@]}" down -v --remove-orphans > /dev/null 2>&1 || true
  exit $status
}
trap cleanup EXIT

"${compose[@]}" up -d --no-build "${services[@]}" test-upstream


wait_healthy() {
  for i in $(seq 1 90); do
    state=$(docker inspect -f '{{.State.Health.Status}}' "$("${compose[@]}" ps -q nginxions)" 2>/dev/null || true)
    [ "$state" = healthy ] && return 0
    [ "$i" = 90 ] && { echo "nginxions is not healthy: $state"; return 1; }
    sleep 2
  done
}

echo "==> waiting for nginxions to become healthy"
wait_healthy
"${compose[@]}" run --rm -T tester

echo "==> restart nginxions"
"${compose[@]}" restart nginxions
wait_healthy
"${compose[@]}" run --rm -T tester after-restart

echo "==> all requested services are still running"
for s in "${services[@]}"; do
  id=$("${compose[@]}" ps -q "$s")
  [ -n "$id" ] && [ "$(docker inspect -f '{{.State.Running}}' "$id")" = true ] || { echo "FAIL: $s is not running"; exit 1; }
done

if [[ " ${services[*]} " == *" crowdsec "* ]]; then
  echo "==> CrowdSec runs locally with the NginxionS bouncer pre-registered"
  "${compose[@]}" exec -T crowdsec cscli bouncers list -o raw | grep -q '^nginxions,' || { echo "FAIL: bouncer nginxions is not registered"; exit 1; }
  "${compose[@]}" exec -T crowdsec cscli bouncers list -o raw | grep -q '^appsec,' || { echo "FAIL: bouncer appsec is not registered"; exit 1; }
  echo "==> NginxionS manages CrowdSec: its machine is registered, the hub index comes from NginxionS"
  "${compose[@]}" exec -T crowdsec cscli machines list -o raw | grep -q '^nginxions-' || { echo "FAIL: the machine of NginxionS is not registered"; exit 1; }
  "${compose[@]}" exec -T crowdsec cscli hub update > /dev/null || { echo "FAIL: cscli hub update does not reach the hub of NginxionS"; exit 1; }
  # smoke banned the tester through the bouncer of NginxionS in nginx: it reads the decisions of the local LAPI
  echo "==> the CrowdSec bouncer of NginxionS pulls decisions from the local LAPI"
  line=$("${compose[@]}" exec -T crowdsec cscli bouncers list -o raw | grep '^nginxions,' || true)
  # name,ip,valid,last_pull,...: last_pull is set after the first pull
  [ -n "$(echo "$line" | cut -d, -f4)" ] || { echo "FAIL: the bouncer of NginxionS never pulled CrowdSec decisions: $line"; exit 1; }
  # the IP reputation of the agent stays off (WAF -> Agent): it would hold every request for a lookup
fi

if [[ " ${services[*]} " == *" openappsec "* ]]; then
  # smoke sent attacks: the agent sends its logs to the local tuning service, which creates its events database
  # with the first one. Without a Fog there is no access token: the agent refused to send them (fixed in openappsec/agent).
  echo "==> the agent's logs reach the local tuning service (its events database exists)"
  for i in $(seq 1 30); do
    db=$("${compose[@]}" exec -T postgres psql -U postgres -tAc \
      "SELECT 1 FROM pg_database WHERE datname = 'i2datatubeschemasecurityeventlogsv03'" 2> /dev/null || true)
    [ "$db" = 1 ] && break
    [ "$i" = 30 ] && { echo "FAIL: the tuning service got no logs of the agent (no events database)"; exit 1; }
    sleep 2
  done
  agent_log=$("${compose[@]}" exec -T openappsec sh -c 'cat /var/log/nano_agent/*.dbg* 2> /dev/null' || true)
  if echo "$agent_log" | grep -q 'Access token is missing'; then
    echo "FAIL: the agent asks for an access token of the Fog to reach a local service"
    exit 1
  fi
  # the agent of NginxionS has no cloud (openappsec/agent): no connection to a Fog is even tried
  if echo "$agent_log" | grep -E 'connected to the Fog|Failed to connect to the Fog|Setting a fog connection'; then
    echo "FAIL: the agent tried to reach a Fog"
    exit 1
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
