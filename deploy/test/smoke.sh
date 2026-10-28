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

  # events of the agent's security log, newest first. The attack is repeated while waiting: the agent
  # restarts its services a few seconds after a start or a new policy, and the event of a request
  # handled just before such a restart can be lost.
  event() {
    for i in $(seq 1 30); do
      status "$SQLI" > /dev/null
      $CURL "$ADMIN/api/npmos/events?important=true&host=test.local" | grep -q "\"action\": *\"$1\"" && return 0
      sleep 2
    done
    fail "no $1 event for test.local in WAF -> Events: $($CURL "$ADMIN/api/npmos/events?kind=all&limit=5")"
  }

  step "WAF -> Events: the blocked attack is an important event (Prevent)"
  event Prevent

  # Agent settings from the GUI: saving restarts the agent, its entrypoint applies them.
  # $1: JSON body, $2: what is checked
  agent_settings() {
    step "WAF -> Agent: $2"
    $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf/agent" -d "$1" \
      | grep -q '"restarting": *true' || fail "saving agent settings did not restart the agent"
    for i in $(seq 1 60); do
      agent=$($CURL "$ADMIN/api/npmos/waf/agent")
      echo "$agent" | grep -q '"restartRequired": *false' && break
      [ "$i" = 60 ] && fail "the agent did not apply its settings: $agent"
      sleep 2
    done
    for i in $(seq 1 60); do
      $CURL "$ADMIN/api/npmos/waf" | grep -q '"reachable": *true' && break
      [ "$i" = 60 ] && fail "the agent did not come back after the restart: $($CURL "$ADMIN/api/npmos/waf")"
      sleep 2
    done
    for i in $(seq 1 60); do
      [ "$(status "$SQLI")" = 403 ] && break
      [ "$i" = 60 ] && fail "SQLi is not blocked after the agent's restart"
      sleep 2
    done
    since=$(date -u +%Y-%m-%dT%H:%M:%S)
    for i in $(seq 1 30); do
      status "$XSS" > /dev/null
      # an event newer than the restart (times are ISO, compared as text)
      $CURL "$ADMIN/api/npmos/events?important=true&host=test.local&limit=1" \
        | grep -o '"time": *"[^"]*"' | cut -d'"' -f4 | awk -v s="$since" '$0 >= s {f=1} END {exit !f}' && return 0
      sleep 2
    done
    fail "attacks after the agent's restart are not in WAF -> Events: $($CURL "$ADMIN/api/npmos/events?kind=all&limit=3")"
  }

  agent_settings '{"crowdsec": {"enabled": false, "mode": "prevent"}, "fail_open": {"enabled": true, "timeout_ms": 100}}' \
    "fail-open timeout from the GUI is applied at the agent's restart, attacks are still blocked and logged"
  agent_settings '{"crowdsec": {"enabled": true, "mode": "prevent"}, "fail_open": {"enabled": true, "timeout_ms": 100}}' \
    "IP reputation from the local CrowdSec on, attacks are still blocked and logged"

  step "WAF -> Policy (expert): an exception for the tester's IP lets the attack through"
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf/policy/custom" -d "{
    \"content\": \"exceptions:\\n  - name: smoke-trusted\\n    action: accept\\n    condition:\\n      - key: sourceIp\\n        value: $client_ip\\npolicies:\\n  default:\\n    exceptions:\\n      - smoke-trusted\\n\",
    \"comment\": \"smoke\"}" > /dev/null
  $CURL "$ADMIN/api/npmos/waf/policy" | grep -q 'name: smoke-trusted' || fail "the exception is not in the policy"
  for i in $(seq 1 60); do
    [ "$(status "$SQLI")" = 200 ] && break
    [ "$i" = 60 ] && fail "SQLi from the trusted IP is still blocked"
    sleep 2
  done

  step "WAF -> Policy (expert): without the fragment (a new empty version) the attack is blocked again"
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf/policy/custom" \
    -d '{"content": "", "comment": "smoke: empty"}' > /dev/null
  for i in $(seq 1 60); do
    [ "$(status "$SQLI")" = 403 ] && break
    [ "$i" = 60 ] && fail "SQLi is not blocked after the exception was removed"
    sleep 2
  done
  $CURL "$ADMIN/api/npmos/waf/policy/custom" | grep -q '"comment": *"smoke: empty"' || fail "versions are not listed"

  step "WAF: detect-learn lets attacks through"
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf/hosts/1" \
    -d '{"enabled": true, "mode": "detect-learn", "minimum_confidence": "high"}' > /dev/null
  for i in $(seq 1 60); do
    [ "$(status "$SQLI")" = 200 ] && break
    [ "$i" = 60 ] && fail "SQLi is still blocked in detect-learn"
    sleep 2
  done

  step "WAF -> Events: the detected attack is an important event (Detect)"
  event Detect
else
  echo "    (agent not running, WAF scenarios skipped)"
fi

# --- phase 2 ---

step "hosts: the upstream of test.local answers, a dead one does not"
$CURL "$ADMIN/api/npmos/hosts/upstreams" | tr -d ' \n' | grep -q '"object_id":1,"host":"test-upstream","port":80,"ok":true' \
  || fail "upstream check of test.local: $($CURL "$ADMIN/api/npmos/hosts/upstreams")"
$CURL -H 'Content-Type: application/json' "$ADMIN/api/nginx/proxy-hosts" -d '{
  "domain_names": ["dead-upstream.local"], "forward_scheme": "http",
  "forward_host": "127.0.0.1", "forward_port": "9"
}' > /dev/null
$CURL "$ADMIN/api/npmos/hosts/upstreams" | tr -d ' \n' | grep -q '"port":9,"ok":false' \
  || fail "a closed port is reported as reachable: $($CURL "$ADMIN/api/npmos/hosts/upstreams")"

step "hosts: who changed test.local and when (audit log)"
$CURL "$ADMIN/api/npmos/hosts/changes" | tr -d ' \n' | grep -q '"type":"proxy-host","object_id":1,' \
  || fail "no last change of test.local: $($CURL "$ADMIN/api/npmos/hosts/changes")"
$CURL "$ADMIN/api/npmos/hosts/changes/proxy-host/1" | grep -q '"action": *"created"' \
  || fail "the history of test.local has no creation: $($CURL "$ADMIN/api/npmos/hosts/changes/proxy-host/1")"

# --- phase 3 ---

step "RBAC: built-in roles exist"
roles=$($CURL "$ADMIN/api/npmos/rbac/roles" | tr -d ' \n')
analyst_role=$(echo "$roles" | grep -o '"id":[0-9]*,"name":"[^"]*","description":"[^"]*","builtin":"security_analyst"' \
  | grep -o '^"id":[0-9]*' | grep -o '[0-9]*')
[ -n "$analyst_role" ] || fail "no Security Analyst role: $roles"

step "RBAC: a Security Analyst"
analyst_id=$($CURL -H 'Content-Type: application/json' "$ADMIN/api/users" \
  -d '{"name": "Analyst", "nickname": "analyst", "email": "analyst@npmos.test", "roles": [], "is_disabled": false}' \
  | tr -d ' \n' | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/users/$analyst_id/auth" \
  -d "{\"type\": \"password\", \"secret\": \"$PASSWORD-analyst\"}" > /dev/null
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/rbac/users/$analyst_id" \
  -d "{\"roles\": [$analyst_role]}" > /dev/null
AJAR=/tmp/analyst-cookies
curl -sS -k -c $AJAR -H 'Content-Type: application/json' "$ADMIN/api/tokens" \
  -d "{\"identity\": \"analyst@npmos.test\", \"secret\": \"$PASSWORD-analyst\"}" > /dev/null
as_analyst() { curl -sS -k -b $AJAR -o /dev/null -w '%{http_code}' "$@"; }
expect() { [ "$1" = "$2" ] || fail "$3: expected $2, got $1"; }

step "RBAC: the analyst sees hosts, WAF and events"
expect "$(as_analyst "$ADMIN/api/nginx/proxy-hosts")" 200 "analyst lists proxy hosts"
expect "$(as_analyst "$ADMIN/api/npmos/events")" 200 "analyst reads WAF events"
expect "$(as_analyst "$ADMIN/api/npmos/waf/policy")" 200 "analyst reads the WAF policy"

step "RBAC: the analyst changes the WAF mode, not the host"
expect "$(as_analyst -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf/hosts/1" \
  -d '{"enabled": true, "mode": "detect-learn", "minimum_confidence": "high"}')" 200 "analyst sets the WAF mode"
expect "$(as_analyst -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginx/proxy-hosts/1" \
  -d '{"forward_port": 81}')" 403 "analyst changes a proxy host"
expect "$(as_analyst -X DELETE "$ADMIN/api/nginx/proxy-hosts/1")" 403 "analyst deletes a proxy host"
expect "$(as_analyst -X POST "$ADMIN/api/npmos/services/npmos/restart")" 403 "analyst restarts a service"
expect "$(as_analyst "$ADMIN/api/users")" 403 "analyst lists users"
expect "$(as_analyst -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/rbac/users/$analyst_id" \
  -d '{"roles": [1]}')" 403 "analyst makes itself an administrator"

step "RBAC: the last administrator keeps the role"
code=$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' \
  "$ADMIN/api/npmos/rbac/users/1" -d '{"roles": []}')
expect "$code" 400 "removing the last administrator"

# --- phase 4 ---

step "events: stored events are filtered and exported"
$CURL "$ADMIN/api/npmos/events?kind=all&limit=1" | grep -q '"total":' || fail "events are not listed"
$CURL "$ADMIN/api/npmos/events/export?format=csv&kind=all" | head -1 | grep -q 'time,severity,action' \
  || fail "CSV export has no header"

step "events: the retention is set in the GUI (not by the analyst)"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/events/settings" \
  -d '{"days": 7, "aggregate_days": 90}' | grep -q '"days": *7' || fail "retention was not saved"
expect "$(as_analyst -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/events/settings" \
  -d '{"days": 1, "aggregate_days": 1}')" 403 "analyst changes the retention"

step "notifications: a webhook channel delivers a test message"
hook=$($CURL -X POST -H 'Content-Type: application/json' "$ADMIN/api/npmos/notifications/channels" \
  -d '{"name": "smoke", "type": "webhook", "config": {"url": "http://test-upstream/npmos-hook", "secret": "k"}}')
hook_id=$(echo "$hook" | grep -o '"id": *[0-9]*' | head -1 | grep -o '[0-9]*$')
[ -n "$hook_id" ] || fail "webhook channel was not created: $hook"
echo "$hook" | grep -q '"secret"' && fail "the webhook secret is returned by the API"
$CURL -X POST "$ADMIN/api/npmos/notifications/channels/$hook_id/test" | grep -q '"ok": *true' \
  || fail "test message through the webhook was not delivered"

step "notifications: an unreachable mail server is an error, not a hang"
mail=$($CURL -X POST -H 'Content-Type: application/json' "$ADMIN/api/npmos/notifications/channels" \
  -d '{"name": "smoke mail", "type": "email", "config": {"host": "127.0.0.1", "port": 2, "security": "none", "from": "npmos@example.test", "to": ["admin@example.test"]}}')
mail_id=$(echo "$mail" | grep -o '"id": *[0-9]*' | head -1 | grep -o '[0-9]*$')
$CURL --max-time 30 -X POST "$ADMIN/api/npmos/notifications/channels/$mail_id/test" | grep -q '"ok": *false' \
  || fail "a mail server that does not answer was not reported"

step "notifications: a rule is created; the analyst cannot add channels"
$CURL -X POST -H 'Content-Type: application/json' "$ADMIN/api/npmos/notifications/rules" \
  -d "{\"name\": \"smoke\", \"type\": \"cert_expiry\", \"params\": {\"days\": 30}, \"channel_ids\": [$hook_id]}" \
  | grep -q '"type": *"cert_expiry"' || fail "rule was not created"
expect "$(as_analyst "$ADMIN/api/npmos/notifications")" 200 "analyst reads notifications"
expect "$(as_analyst -X POST -H 'Content-Type: application/json' "$ADMIN/api/npmos/notifications/channels" \
  -d '{"name": "x", "type": "webhook", "config": {"url": "http://x"}}')" 403 "analyst adds a channel"

step "system settings: an env setting is saved for the next start, a bad value is refused"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/system/settings" \
  -d '{"values": [{"env": "NGINX_LOG_NOT_FOUND", "value": true}]}' | grep -q '"restartRequired": *true' \
  || fail "a saved env setting is not pending"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/system/settings" \
  -d '{"values": [{"env": "NGINX_LOG_NOT_FOUND", "value": false}]}' | grep -q '"restartRequired": *false' \
  || fail "the setting back to its running value is still pending"
code=$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' \
  "$ADMIN/api/npmos/system/settings" -d '{"values": [{"env": "TZ", "value": "../../etc/passwd"}]}')
expect "$code" 400 "a bad time zone"
expect "$(as_analyst -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/system/settings" \
  -d '{"values": [{"env": "DISABLE_HTTP", "value": true}]}')" 403 "analyst changes system settings"

echo "OK: closed-network smoke passed"
