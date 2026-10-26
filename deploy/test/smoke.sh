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

echo "OK: closed-network smoke passed"
