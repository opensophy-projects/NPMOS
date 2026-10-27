#!/bin/sh
# Smoke scenarios run inside the closed network against a fresh stack.
# Each phase appends its scenarios here.
set -eu

ADMIN="https://npmos:81"
HTTP="http://npmos"
EMAIL="admin@npmos.test"
PASSWORD="npmos-airgap-$(date +%s)"
# cookie jar on a volume shared between tester runs (session must survive an npmos restart)
JAR=/state/cookies
CURL="curl -sS --fail-with-body --max-time 30 -k -b $JAR -c $JAR"

step() { echo "==> $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

wait_api() {
  for i in $(seq 1 60); do
    $CURL "$ADMIN/api/" 2>/dev/null | grep -q '"status": *"OK"' && return 0
    sleep 2
  done
  fail "admin API did not become ready"
}

if [ "${1:-}" = after-restart ]; then
  step "session is still valid after npmos restart (persistent COOKIE_SECRET)"
  wait_api
  $CURL "$ADMIN/api/users/me" | grep -q '"email": *"admin@npmos.test"' || fail "session lost after restart"
  echo "OK: after-restart scenarios passed"
  exit 0
fi

step "admin API is up"
wait_api

step "initial setup: create the first admin"
$CURL -H 'Content-Type: application/json' "$ADMIN/api/users" -d "{
  \"name\": \"Admin\", \"nickname\": \"admin\", \"email\": \"$EMAIL\",
  \"auth\": {\"type\": \"password\", \"secret\": \"$PASSWORD\"}
}" > /dev/null

step "log in"
$CURL -H 'Content-Type: application/json' "$ADMIN/api/tokens" \
  -d "{\"identity\": \"$EMAIL\", \"secret\": \"$PASSWORD\"}" > /dev/null

step "duplicate email is rejected and does not crash the backend"
code=$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' "$ADMIN/api/users" \
  -d "{\"name\": \"Dup\", \"nickname\": \"dup\", \"email\": \"$EMAIL\"}")
[ "$code" = 400 ] || fail "duplicate email: expected 400, got $code"
sleep 2
$CURL "$ADMIN/api/" | grep -q '"status": *"OK"' || fail "backend is down after duplicate email"

step "create a proxy host test.local -> test-upstream"
$CURL -H 'Content-Type: application/json' "$ADMIN/api/nginx/proxy-hosts" -d '{
  "domain_names": ["test.local"], "forward_scheme": "http",
  "forward_host": "test-upstream", "forward_port": "80"
}' > /dev/null

step "request goes through the proxy"
for i in $(seq 1 15); do
  body=$(curl -sS --max-time 10 -H 'Host: test.local' "$HTTP/" || true)
  echo "$body" | grep -q '^Hostname:' && break
  [ "$i" = 15 ] && fail "proxy host did not answer: $body"
  sleep 2
done

step "upstream sees the real client IP"
client_ip=$(hostname -i | awk '{print $1}')
echo "$body" | grep -qiE "^X-(Real-Ip|Forwarded-For): .*$client_ip" || fail "client IP $client_ip not forwarded: $body"

step "update check stays off"
$CURL "$ADMIN/api/version/check" | grep -q '"latest": *"unknown"' || fail "update check is not disabled"

# --- phase 1 ---

step "System → Services: npmos-control lists the stack"
services=$($CURL "$ADMIN/api/npmos/services")
for s in npmos postgres npmos-control; do
  echo "$services" | grep -q "\"service\": *\"$s\"" || fail "service $s is not listed: $services"
done

step "System → Services: service logs are readable"
$CURL "$ADMIN/api/npmos/services/npmos/logs?tail=20" | grep -q '"line"' || fail "no npmos logs"

step "System → Services: the control path cannot be restarted"
code=$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' -X POST "$ADMIN/api/npmos/services/socket-proxy/restart")
[ "$code" = 400 ] || fail "socket-proxy restart: expected 400, got $code"

step "System → Services: restart postgres, the backend reconnects"
$CURL -X POST "$ADMIN/api/npmos/services/postgres/restart" | grep -q '"restarted": *true' || fail "postgres restart failed"
for i in $(seq 1 30); do
  $CURL "$ADMIN/api/users/me" 2>/dev/null | grep -q "$EMAIL" && break
  [ "$i" = 30 ] && fail "backend did not reconnect to postgres"
  sleep 2
done
$CURL "$ADMIN/api/audit-log" | grep -q '"action": *"restarted"' || fail "restart is not in the audit log"

step "System → Services: regenerate nginx config, the proxy host still answers"
$CURL -X POST "$ADMIN/api/npmos/nginx/regenerate" | grep -q '"regenerated": *true' || fail "regenerate failed"
curl -sS --max-time 10 -H 'Host: test.local' "$HTTP/" | grep -q '^Hostname:' || fail "proxy host is down after regenerate"

step "System → Services: diagnostic archive"
$CURL -o /tmp/diagnostics.zip "$ADMIN/api/npmos/diagnostics"
[ "$(head -c 2 /tmp/diagnostics.zip)" = PK ] || fail "diagnostic archive is not a zip"

step "WAF: protecting a proxy host generates its rule in local_policy.yaml"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf/hosts/1" \
  -d '{"enabled": true, "mode": "prevent-learn", "minimum_confidence": "high"}' > /dev/null
for i in $(seq 1 10); do
  $CURL "$ADMIN/api/npmos/waf/policy" | grep -q 'host: test.local\\n *name: npm-managed-specific-rule-proxyhost-1\\n' && break
  [ "$i" = 10 ] && fail "no rule for test.local in the policy: $($CURL "$ADMIN/api/npmos/waf/policy")"
  sleep 1
done
$CURL "$ADMIN/api/npmos/waf/policy" | grep -q 'mode: prevent-learn' || fail "the rule is not in prevent-learn"

if $CURL "$ADMIN/api/npmos/waf" | grep -q '"reachable": *true'; then
  step "WAF: switch open-appsec on in the GUI (npmos restarts with the nginx attachment)"
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf" -d '{"enabled": true, "apply": true}' \
    | grep -q '"restarting": *true' || fail "WAF switch did not restart npmos"
  # npmos-control answers first, then restarts npmos and the agent in its namespaces
  sleep 5
  wait_api
  for i in $(seq 1 30); do
    $CURL "$ADMIN/api/npmos/waf" | grep -q '"active": *true' && break
    [ "$i" = 30 ] && fail "attachment is not active: $($CURL "$ADMIN/api/npmos/waf")"
    sleep 2
  done

  step "WAF: the open-appsec agent applies its policy without internet (local-only mode)"
  for i in $(seq 1 90); do
    $CURL "$ADMIN/api/npmos/waf" | grep -q '"lastPolicyUpdate": *"' && break
    [ "$i" = 90 ] && fail "agent did not apply a policy: $($CURL "$ADMIN/api/npmos/waf")"
    sleep 2
  done

  status() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: test.local' "$HTTP$1"; }
  SQLI="/?id=1%27%20OR%20%271%27=%271"
  XSS="/?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"

  step "WAF: prevent-learn blocks SQLi and XSS with 403, normal requests pass"
  for i in $(seq 1 60); do
    [ "$(status "$SQLI")" = 403 ] && break
    [ "$i" = 60 ] && fail "SQLi was not blocked (last status $(status "$SQLI"))"
    sleep 2
  done
  [ "$(status "$XSS")" = 403 ] || fail "XSS was not blocked"
  [ "$(status "/?q=hello")" = 200 ] || fail "a normal request was blocked"

  step "WAF: detect-learn lets attacks through"
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf/hosts/1" \
    -d '{"enabled": true, "mode": "detect-learn", "minimum_confidence": "high"}' > /dev/null
  for i in $(seq 1 60); do
    [ "$(status "$SQLI")" = 200 ] && break
    [ "$i" = 60 ] && fail "SQLi is still blocked in detect-learn"
    sleep 2
  done
else
  echo "    (agent not running, WAF scenarios skipped)"
fi

echo "OK: closed-network smoke passed"
