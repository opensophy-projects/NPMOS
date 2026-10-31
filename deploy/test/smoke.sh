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
  $CURL "$ADMIN/api/npmos/waf/policy" | grep -q 'name: npm-managed-specific-rule-proxyhost-1\\n *host: test.local\\n' && break
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
  # a request handled while the agent restarts a service (after a new policy) can pass: retried
  for i in $(seq 1 30); do
    [ "$(status "$XSS")" = 403 ] && break
    [ "$i" = 30 ] && fail "XSS was not blocked"
    sleep 2
  done
  [ "$(status "/?q=hello")" = 200 ] || fail "a normal request was blocked"

  step "WAF: the request headers of a browser pass (a stylesheet of Chrome: Sec-Fetch-Dest: style)"
  # the agent's model takes "style" for XSS: without waap-headers.json every stylesheet of Chrome was refused
  browser=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: test.local' -H 'Accept: text/css,*/*;q=0.1' \
    -H 'Sec-Fetch-Dest: style' -H 'Sec-Fetch-Mode: no-cors' -H 'Sec-Fetch-Site: same-origin' -H 'Priority: u=0' \
    -H 'Sec-Ch-Ua-Mobile: ?0' -H 'Sec-Ch-Ua-Platform: "Linux"' "$HTTP/assets/index.css")
  [ "$browser" = 403 ] && fail "a stylesheet request of a browser was blocked"
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: test.local' \
    -H 'Sec-Fetch-Dest: <script>alert(document.cookie)</script>' "$HTTP/")" = 403 ] \
    || fail "an attack in Sec-Fetch-Dest was not blocked"

  step "Block page: a refused request gets the page of NPMOS, not the one of the agent"
  page=$(curl -s --max-time 10 -H 'Host: test.local' "$HTTP$SQLI")
  echo "$page" | grep -q 'NPMOS: block page' || fail "no block page of NPMOS: $(echo "$page" | head -c 300)"
  echo "$page" | grep -q 'Check Point' && fail "the page of the agent is shown"
  echo "$page" | grep -q '{{ip}}' && fail "the details of the request are not filled in"

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
    # npmos restarts with the agent: the API is away for a while (connections are reset)
    for i in $(seq 1 60); do
      agent=$($CURL "$ADMIN/api/npmos/waf/agent" 2>/dev/null || true)
      echo "$agent" | grep -q '"restartRequired": *false' && break
      [ "$i" = 60 ] && fail "the agent did not apply its settings: $agent"
      sleep 2
    done
    for i in $(seq 1 60); do
      $CURL "$ADMIN/api/npmos/waf" 2>/dev/null | grep -q '"reachable": *true' && break
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

  agent_settings '{"fail_open": {"enabled": true, "timeout_ms": 100}}' \
    "fail-open timeout from the GUI is applied at the agent's restart, attacks are still blocked and logged"
  agent_settings '{"fail_open": {"enabled": true, "timeout_ms": 50}}' \
    "a second change is applied the same way"

  # applying agent settings restarts npmos with the agent: restarted alone, the agent left the nginx
  # attachment without its IPC and every request waited for it (about 1-2 s)
  step "WAF -> Agent: after the agent's restart requests are not held up"
  slow=0
  for i in $(seq 1 10); do
    t=$(curl -s -o /dev/null -w '%{time_total}' --max-time 10 -H 'Host: test.local' "$HTTP/")
    awk -v t="$t" 'BEGIN {exit !(t > 0.5)}' && slow=$((slow + 1))
  done
  [ "$slow" -le 1 ] || fail "$slow of 10 requests took more than 0.5 s after the agent's restart"
  t=$($CURL -o /dev/null -w '%{time_total}' "$ADMIN/api/")
  awk -v t="$t" 'BEGIN {exit !(t > 0.5)}' && fail "the interface took $t s: it must not wait for the agent"

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

  # WAF -> Policy (phase 5): objects of the policy through the API of the GUI
  json() { tr -d ' \n'; }
  object_id() {
    $CURL "$ADMIN/api/npmos/waf/policy/objects" | json \
      | grep -o "\"id\":[0-9]*,[^{}]*\"kind\":\"$1\",\"name\":\"$2\"" | head -1 | sed 's/"id":\([0-9]*\).*/\1/'
  }
  new_id() { json | grep -o '^{"id":[0-9]*' | grep -o '[0-9]*$'; }
  last_version() { $CURL "$ADMIN/api/npmos/waf/policy/versions" | json | grep -o '^\[{"id":[0-9]*' | grep -o '[0-9]*$'; }
  post_json() { $CURL -X "$1" -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf/policy$2" -d "$3"; }
  wait_status() {
    for i in $(seq 1 60); do
      [ "$(status "$1")" = "$2" ] && return 0
      sleep 2
    done
    fail "$3 (last status $(status "$1"))"
  }

  step "WAF -> Policy: an exception object in the default policy lets the attack through, a rollback blocks it again"
  recommended=$(object_id threat_prevention npmos-recommended)
  trigger=$(object_id log_trigger npmos-log)
  response=$(object_id custom_response npmos-403)
  [ -n "$recommended" ] && [ -n "$trigger" ] && [ -n "$response" ] || fail "built-in objects are missing"
  exception=$(post_json POST /objects "{\"kind\": \"exception\", \"name\": \"smoke-office\",
    \"spec\": {\"action\": \"accept\", \"condition\": [{\"key\": \"sourceIp\", \"value\": \"192.0.2.1\"},
    {\"key\": \"sourceIp\", \"value\": \"$client_ip\"}]}}" | new_id)
  [ -n "$exception" ] || fail "the exception was not created"
  before=$(last_version)
  default_policy="{\"mode\": \"inactive\", \"threatPreventionPractices\": [$recommended], \"triggers\": [$trigger],
    \"customResponse\": $response"
  post_json POST /preview "{\"policy\": $default_policy, \"exceptions\": [$exception]}}" | json \
    | grep -q '"valid":true,"changed":true' || fail "the preview of the default policy is not valid"
  post_json PUT /default "$default_policy, \"exceptions\": [$exception]}" > /dev/null
  $CURL "$ADMIN/api/npmos/waf/policy" | grep -q -- "- $client_ip" || fail "the exception is not in local_policy.yaml (v1beta1 lists)"
  wait_status "$SQLI" 200 "SQLi from an IP of the exception is still blocked"
  [ "$($CURL -o /dev/null -w "%{http_code}" -X DELETE "$ADMIN/api/npmos/waf/policy/objects/$exception" 2>/dev/null || true)" = 400 ] \
    || fail "an object in use was deleted"
  post_json POST "/versions/$before/rollback" "" > /dev/null
  wait_status "$SQLI" 403 "SQLi is not blocked after the rollback"

  step "WAF -> Policy: a rate limit of the host switches local_policy.yaml to v1beta2 and limits requests"
  limit=$(post_json POST /objects '{"kind": "access_control", "name": "smoke-limit",
    "spec": {"rateLimit": {"overrideMode": "prevent", "rules": [{"uri": "/smoke-limit", "limit": 3, "unit": "minute"}]}}}' \
    | new_id)
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf/hosts/1" -d "{\"enabled\": true,
    \"mode\": \"prevent-learn\", \"minimum_confidence\": \"high\", \"objects\": {\"accessControlPractices\": [$limit]}}" > /dev/null
  for i in $(seq 1 30); do
    $CURL "$ADMIN/api/npmos/waf/policy" | grep -q '"format": *"v1beta2"' && break
    [ "$i" = 30 ] && fail "the policy is not v1beta2: $($CURL "$ADMIN/api/npmos/waf/policy" | head -c 400)"
    sleep 1
  done
  limited=""
  for i in $(seq 1 60); do
    for _ in 1 2 3 4 5 6; do
      [ "$(status /smoke-limit)" = 403 ] && limited=1
    done
    [ -n "$limited" ] && break
    [ "$i" = 60 ] && fail "requests over the rate limit are not blocked"
    sleep 2
  done
  [ "$(status /)" = 200 ] || fail "a path without a rate limit is blocked"
  wait_status "$SQLI" 403 "SQLi is not blocked with the v1beta2 policy"
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf/hosts/1" \
    -d '{"enabled": true, "mode": "prevent-learn", "minimum_confidence": "high", "objects": null}' > /dev/null
  # the policy is generated again a moment after the host changes
  for i in $(seq 1 30); do
    $CURL "$ADMIN/api/npmos/waf/policy" | grep -q '"format": *"v1beta1"' && break
    [ "$i" = 30 ] && fail "the policy is not back to v1beta1: $($CURL "$ADMIN/api/npmos/waf/policy" | head -c 400)"
    sleep 1
  done

  step "WAF -> Policy: the v1beta2 example of open-appsec is imported and applied by the agent"
  applied_at() { $CURL "$ADMIN/api/npmos/waf" | json | grep -o '"lastPolicyUpdate":"[^"]*"'; }
  before=$(last_version)
  previous=$(applied_at)
  example=$(sed 's/\\/\\\\/g; s/"/\\"/g' /reference/v1beta2-example.yaml | awk '{printf "%s\\n", $0}')
  post_json POST "/import?dry_run=true" "{\"content\": \"$example\"}" | json | grep -q '"errors":\[\]' \
    || fail "the example is not imported: $(post_json POST "/import?dry_run=true" "{\"content\": \"$example\"}")"
  post_json POST /import "{\"content\": \"$example\"}" | json | grep -q '"applied":true' || fail "the import was not applied"
  for i in $(seq 1 60); do
    [ "$(applied_at)" != "$previous" ] && break
    [ "$i" = 60 ] && fail "the agent did not apply the imported policy"
    sleep 2
  done
  post_json POST "/versions/$before/rollback" "" > /dev/null
  wait_status "$SQLI" 403 "SQLi is not blocked after the rollback of the import"

  step "Learning: the blocked attack is a group of the queue of its host"
  key=""
  for i in $(seq 1 30); do
    key=$($CURL "$ADMIN/api/npmos/learning/queue?period=24h&host=1&reason=blocked&suggestions=0" \
      | grep -o '"key": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{32\}' || true)
    [ -n "$key" ] && break
    [ "$i" = 30 ] && fail "no blocked group for test.local: $($CURL "$ADMIN/api/npmos/learning/queue?period=24h")"
    status "$SQLI" > /dev/null
    sleep 2
  done

  step "Learning: labelled legitimate with an exception, the attack passes at once; undo blocks it again"
  label=$($CURL -H 'Content-Type: application/json' "$ADMIN/api/npmos/learning/labels" -d "{\"key\": \"$key\", \"decision\": \"benign\",
    \"scopes\": [{\"type\": \"parameterName\", \"value\": \"id\"}], \"exception\": true, \"ttl_days\": 1}")
  label_id=$(echo "$label" | grep -o '"id": *[0-9]*' | head -1 | grep -o '[0-9]*$')
  # decisions.data of the assets of the host is written in the shared storage, where the agent reads it
  echo "$label" | grep -q '"syncError": *""' || fail "the label was not written for the agent: $label"
  echo "$label" | grep -q '"syncedOn": *"' || fail "the label was not written for the agent: $label"
  $CURL "$ADMIN/api/npmos/learning/queue?period=24h&host=1&suggestions=0" | grep -q "\"$key\"" \
    && fail "the labelled group is still in the queue"
  wait_status "$SQLI" 200 "SQLi labelled legitimate is still blocked"
  $CURL "$ADMIN/api/npmos/waf/policy" | grep -q "npmos-learn-$label_id" || fail "no exception of the label in the policy"
  $CURL -X DELETE "$ADMIN/api/npmos/learning/labels/$label_id" | grep -q '"ok": *true' || fail "the label was not undone"
  wait_status "$SQLI" 403 "SQLi is not blocked after the label was undone"
  $CURL "$ADMIN/api/npmos/learning/labels?active=0" | grep -q '"undoneOn": *"' || fail "the undone label is not in the history"

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

step "RBAC: a role of chosen hosts sees test.local, not another host of the administrator"
other_id=$($CURL -H 'Content-Type: application/json' "$ADMIN/api/nginx/proxy-hosts" -d '{
  "domain_names": ["other.local"], "forward_scheme": "http", "forward_host": "test-upstream", "forward_port": "80"
}' | tr -d ' \n' | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')
scoped_role=$($CURL -H 'Content-Type: application/json' "$ADMIN/api/npmos/rbac/roles" -d '{"name": "test.local team",
  "scope": "hosts", "hosts": [{"host_type": "proxy_host", "host_id": 1}], "permissions": ["proxy_hosts:view"]}' \
  | tr -d ' \n' | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/rbac/users/$analyst_id" \
  -d "{\"roles\": [$scoped_role]}" > /dev/null
seen=$(curl -sS -k -b $AJAR "$ADMIN/api/nginx/proxy-hosts" | tr -d ' \n')
echo "$seen" | grep -q '"domain_names":\["test.local"\]' || fail "the role does not see its host: $seen"
echo "$seen" | grep -q 'other.local' && fail "the role sees a host it was not given: $seen"
expect "$(as_analyst "$ADMIN/api/nginx/proxy-hosts/$other_id")" 404 "the role opens a host it was not given"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/rbac/users/$analyst_id" \
  -d "{\"roles\": [$analyst_role]}" > /dev/null
$CURL -X DELETE "$ADMIN/api/nginx/proxy-hosts/$other_id" > /dev/null

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

# --- phase 6 ---

# the first number "id" of a JSON answer
json_id() { tr -d ' \n' | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*$'; }
# a PEM field of a JSON answer as a file
json_pem() { tr -d '\n' | sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" | awk '{ gsub(/\\n/, "\n"); printf "%s", $0 }' > "$2"; }
api_json() { $CURL -H 'Content-Type: application/json' "$@"; }
HTTPS_MTLS="https://mtls.local"
TLS_TO="--connect-to mtls.local:443:npmos:443"

step "PKI: a root CA and a trust domain"
root_id=$(api_json "$ADMIN/api/npmos/pki/cas" \
  -d '{"kind": "root", "name": "Smoke Root", "subject": {"common_name": "Smoke Root", "organization": "NPMOS"}}' | json_id)
[ -n "$root_id" ] || fail "root CA was not created"
domain_id=$(api_json "$ADMIN/api/npmos/pki/cas" -d "{\"kind\": \"intermediate\", \"name\": \"Smoke Office\",
  \"parent_id\": $root_id, \"subject\": {\"common_name\": \"Smoke Office\", \"organization\": \"NPMOS\"}}" | json_id)
[ -n "$domain_id" ] || fail "trust domain was not created"
other_id=$(api_json "$ADMIN/api/npmos/pki/cas" -d "{\"kind\": \"intermediate\", \"name\": \"Smoke Partners\",
  \"parent_id\": $root_id, \"subject\": {\"common_name\": \"Smoke Partners\", \"organization\": \"NPMOS\"}}" | json_id)
expect "$(as_analyst -X POST -H 'Content-Type: application/json' "$ADMIN/api/npmos/pki/cas" \
  -d '{"kind": "root", "name": "x", "subject": {"common_name": "x"}}')" 403 "analyst creates a CA"

step "PKI: a server certificate of the trust domain becomes a certificate of NPMplus"
server=$(api_json "$ADMIN/api/npmos/pki/certs" -d "{\"ca_id\": $domain_id, \"profile\": \"server\",
  \"subject\": {\"common_name\": \"mtls.local\"}, \"sans\": {\"dns\": [\"mtls.local\"]}, \"install\": true}")
tls_id=$(echo "$server" | tr -d ' \n' | grep -o '"certificate_id":[0-9]*' | grep -o '[0-9]*$')
[ -n "$tls_id" ] || fail "server certificate was not installed: $server"
host_id=$(api_json "$ADMIN/api/nginx/proxy-hosts" -d "{\"domain_names\": [\"mtls.local\"], \"forward_scheme\": \"http\",
  \"forward_host\": \"test-upstream\", \"forward_port\": \"80\", \"certificate_id\": $tls_id}" | json_id)
[ -n "$host_id" ] || fail "proxy host mtls.local was not created"

step "mTLS: the host requires a certificate of the trust domain with OU=IT"
api_json -X PUT "$ADMIN/api/npmos/mtls/proxy_host/$host_id" -d "{\"enabled\": true, \"ca_ids\": [$domain_id],
  \"rules\": [{\"field\": \"organizational_unit\", \"op\": \"one_of\", \"values\": [\"IT\"]}]}" \
  | tr -d ' \n' | grep -q '"nginx_online":true' || fail "nginx did not take the mTLS of the host"

# a client certificate as PEM files (the tester has no openssl to open a .p12)
client() { # name, OU, CA id → /tmp/<name>.crt, /tmp/<name>.key
  answer=$(api_json "$ADMIN/api/npmos/pki/certs" -d "{\"ca_id\": $3, \"profile\": \"client\",
    \"subject\": {\"common_name\": \"$1\", \"organizational_unit\": \"$2\"}, \"include_key_pem\": true, \"link_hours\": 1}")
  echo "$answer" | json_pem cert_pem "/tmp/$1.crt"
  echo "$answer" | json_pem key_pem "/tmp/$1.key"
  grep -q 'BEGIN CERTIFICATE' "/tmp/$1.crt" || fail "no certificate for $1: $answer"
  echo "$answer"
}
alice=$(client alice IT "$domain_id")
client bob Sales "$domain_id" > /dev/null
client carol IT "$other_id" > /dev/null
mtls() { curl -sS -k --max-time 10 $TLS_TO -o /dev/null -w '%{http_code}' "$@" "$HTTPS_MTLS/"; }

for i in $(seq 1 15); do
  [ "$(mtls --cert /tmp/alice.crt --key /tmp/alice.key)" = 200 ] && break
  [ "$i" = 15 ] && fail "the host does not let alice in"
  sleep 2
done
body=$(curl -sS -k --max-time 10 $TLS_TO --cert /tmp/alice.crt --key /tmp/alice.key -H 'X-Client-Verify: FAKE' "$HTTPS_MTLS/")
echo "$body" | grep -q '^X-Client-Verify: SUCCESS' || fail "the upstream did not get X-Client-Verify: $body"
echo "$body" | grep -q '^X-Client-S-Dn: CN=alice,OU=IT' || fail "the upstream did not get the subject: $body"
echo "$body" | grep -q 'FAKE' && fail "a spoofed X-Client-Verify reached the upstream"
expect "$(mtls)" 403 "no client certificate"

step "mTLS: the refused request is a security event"
for i in $(seq 1 15); do
  $CURL "$ADMIN/api/npmos/events?kind=mtls&limit=5" | grep -q '"name": *"mTLS: no client certificate"' && break
  [ "$i" = 15 ] && fail "no mTLS event: $($CURL "$ADMIN/api/npmos/events?kind=mtls&limit=5")"
  sleep 2
done
curl -sS -k --max-time 10 $TLS_TO "$HTTPS_MTLS/" | grep -q 'client certificate is required' \
  || fail "no explanation page without a certificate"
expect "$(mtls --cert /tmp/bob.crt --key /tmp/bob.key)" 403 "a certificate with OU=Sales"
expect "$(mtls --cert /tmp/carol.crt --key /tmp/carol.key)" 403 "a certificate of another trust domain"

step "PKI: the one-time link opens once, the CRL is published"
link=$(echo "$alice" | tr -d ' \n' | grep -o '"path":"[^"]*"' | cut -d'"' -f4)
[ -n "$link" ] || fail "no one-time link"
expect "$(curl -sS -k -o /dev/null -w '%{http_code}' "$ADMIN$link")" 200 "the one-time link"
expect "$(curl -sS -k -o /dev/null -w '%{http_code}' "$ADMIN$link")" 410 "the one-time link again"
expect "$(curl -sS -k -o /dev/null -w '%{http_code}' "$ADMIN/api/npmos/pki/public/crl/$domain_id.crl")" 200 "the CRL"

step "PKI: a revoked certificate is refused within a minute"
alice_id=$(echo "$alice" | tr -d ' \n' | grep -o '"certificate":{"id":[0-9]*' | grep -o '[0-9]*$')
api_json "$ADMIN/api/npmos/pki/certs/revoke" -d "{\"ids\": [$alice_id], \"reason\": \"keyCompromise\"}" \
  | grep -q '"revoked": *1' || fail "alice was not revoked"
for i in $(seq 1 30); do
  [ "$(mtls --cert /tmp/alice.crt --key /tmp/alice.key)" = 403 ] && break
  [ "$i" = 30 ] && fail "the revoked certificate still opens the host after a minute"
  sleep 2
done

step "mTLS in one step: the switch of a host creates its trust domain, an access certificate opens it"
quick_id=$(api_json "$ADMIN/api/nginx/proxy-hosts" -d "{\"domain_names\": [\"quick.local\"], \"forward_scheme\": \"http\",
  \"forward_host\": \"test-upstream\", \"forward_port\": \"80\", \"certificate_id\": $tls_id}" | json_id)
[ -n "$quick_id" ] || fail "proxy host quick.local was not created"
quick=$(api_json -X POST "$ADMIN/api/npmos/mtls/proxy_host/$quick_id/enable" | tr -d ' \n')
echo "$quick" | grep -q '"enabled":true' || fail "mTLS was not turned on: $quick"
quick_ca=$(echo "$quick" | grep -o '"ca_ids":\[[0-9]*' | grep -o '[0-9]*$')
$CURL "$ADMIN/api/npmos/pki/cas/$quick_ca" | grep -q '"host": *"proxy_host-'"$quick_id"'"' \
  || fail "the trust domain of quick.local is not its own"
dana=$(client dana IT "$quick_ca")
quick_mtls() { curl -sS -k --max-time 10 --connect-to quick.local:443:npmos:443 -o /dev/null -w '%{http_code}' "$@" https://quick.local/; }
for i in $(seq 1 15); do
  [ "$(quick_mtls --cert /tmp/dana.crt --key /tmp/dana.key)" = 200 ] && break
  [ "$i" = 15 ] && fail "the access certificate does not open quick.local"
  sleep 2
done
expect "$(quick_mtls)" 403 "quick.local without a certificate"
expect "$(quick_mtls --cert /tmp/carol.crt --key /tmp/carol.key)" 403 "quick.local with a certificate of another domain"
expect "$(mtls --cert /tmp/dana.crt --key /tmp/dana.key)" 403 "mtls.local with the access certificate of quick.local"
# dana is the only certificate of the trust domain of quick.local
$CURL "$ADMIN/api/npmos/pki" | tr -d ' \n' | grep -q '{"host_type":"proxy_host","host_id":'"$quick_id"',"name":"quick.local"}' \
  || fail "the certificate does not list quick.local as what it opens"

step "mTLS: a deleted access certificate is revoked and gone from the list"
dana_id=$(echo "$dana" | tr -d ' \n' | grep -o '"certificate":{"id":[0-9]*' | grep -o '[0-9]*$')
api_json "$ADMIN/api/npmos/pki/certs/delete" -d "{\"ids\": [$dana_id]}" | tr -d ' \n' \
  | grep -q '"deleted":1,"revoked":1' || fail "dana was not deleted"
for i in $(seq 1 30); do
  [ "$(quick_mtls --cert /tmp/dana.crt --key /tmp/dana.key)" = 403 ] && break
  [ "$i" = 30 ] && fail "the deleted certificate still opens quick.local"
  sleep 2
done
$CURL "$ADMIN/api/npmos/pki" | grep -q '"common_name": *"dana"' && fail "the deleted certificate is still listed"

step "Certificates: the registry lists the TLS certificate and the CAs of the PKI, without the deleted one"
registry=$($CURL "$ADMIN/api/npmos/certificates?limit=200" | tr -d ' \n')
echo "$registry" | grep -q '"source":"tls"' || fail "no TLS certificate in the registry: $registry"
echo "$registry" | grep -q '"name":"SmokeOffice"' || fail "no trust domain in the registry: $registry"
echo "$registry" | grep -q '"name":"dana"' && fail "the deleted certificate is in the registry"
$CURL "$ADMIN/api/npmos/certificates?source=pki&status=revoked&q=alice" | grep -q '"name": *"alice"' \
  || fail "the revoked certificate is not found by its status"

step "Audit log: pages from the server and the action filter"
audit=$($CURL "$ADMIN/api/npmos/audit?action=revoked&limit=1" | tr -d ' \n')
echo "$audit" | grep -q '"action":"revoked"' || fail "no revoked entry in the audit log: $audit"
echo "$audit" | grep -q '"total":[1-9]' || fail "the audit log has no total: $audit"

# --- phase 7 ---

page() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: test.local' "$HTTP$1"; }
wait_page() { # path, code, message
  for i in $(seq 1 15); do
    [ "$(page "$1")" = "$2" ] && return 0
    sleep 2
  done
  fail "$3: expected $2, got $(page "$1")"
}
# settings of CrowdSec: AppSec on/off, the filter of the only profile
cs_settings() {
  $CURL --max-time 300 -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/crowdsec/settings" -d "{
  \"bouncer\": {\"enabled\": true, \"admin\": false, \"mode\": \"live\", \"fallback\": \"ban\", \"update_frequency\": 10,
    \"exclude_locations\": [], \"captcha\": {\"provider\": \"\", \"site_key\": \"\", \"secret_key\": \"\"}},
  \"sources\": {\"nginx\": true, \"openappsec\": true},
  \"appsec\": {\"enabled\": $1, \"failure_action\": \"passthrough\", \"configs\": [\"crowdsecurity/appsec-default\"]},
  \"profiles\": [{\"name\": \"ip\", \"enabled\": true, \"scope\": \"Ip\", \"scenarios\": [], \"filter\": \"$2\",
    \"type\": \"ban\", \"duration\": \"4h\", \"escalate\": false}],
  \"allowlist\": {\"ips\": [], \"expressions\": [], \"private\": false},
  \"openappsec_ban\": {\"enabled\": true, \"events\": 3, \"minutes\": 10}, \"log_level\": \"info\", \"online_hub\": false}"
}

step "CrowdSec: the local API answers, NPMOS is a machine of its own"
for i in $(seq 1 30); do
  $CURL "$ADMIN/api/npmos/crowdsec" | tr -d ' \n' | grep -q '"lapi":{"healthy":true' && break
  [ "$i" = 30 ] && fail "the local API of CrowdSec does not answer: $($CURL "$ADMIN/api/npmos/crowdsec")"
  sleep 2
done
$CURL "$ADMIN/api/npmos/crowdsec/registry" | grep -q '"name": *"npmos-' || fail "NPMOS is not a machine of CrowdSec"

# the closed network has private addresses only: they are not allowlisted here
step "CrowdSec: settings from the GUI are applied (bouncer and AppSec on)"
cs_settings true "" | tr -d ' \n' | grep -q '"\(restarted\|reloaded\)":true' || fail "the settings were not applied"

# profiles, acquisition, allowlists and scenarios are reread on SIGHUP: no restart of the container
step "CrowdSec: a change of a profile is applied by a reload, not a restart"
cs_started() { $CURL "$ADMIN/api/npmos/services/crowdsec" | grep -o '"startedAt": *"[^"]*"'; }
before=$(cs_started)
cs_settings true "Alert.GetScope() == 'Ip'" | tr -d ' \n' | grep -q '"reloaded":true' \
  || fail "the profile change was not applied by a reload"
[ "$(cs_started)" = "$before" ] || fail "CrowdSec was restarted for a profile change"

step "CrowdSec: a broken profile is refused at the start of CrowdSec, the previous files come back"
answer=$(cs_settings true "Alert.Broken(((" 2>&1 || true)
echo "$answer" | grep -q 'previous ones are restored' || fail "a broken profile was not rolled back: $answer"
$CURL "$ADMIN/api/npmos/crowdsec" | tr -d ' \n' | grep -q '"lapi":{"healthy":true' \
  || fail "CrowdSec is not healthy after the rollback"
# the filter of the previous step comes back, not the broken one
$CURL "$ADMIN/api/npmos/crowdsec/settings" | grep -q 'Alert.Broken' && fail "the broken profile was kept"
$CURL "$ADMIN/api/npmos/crowdsec/settings" | grep -q "Alert.GetScope() == 'Ip'" || fail "the previous profile did not come back"

step "CrowdSec: a ban by hand blocks the tester on its hosts, not in the interface of NPMOS"
api_json "$ADMIN/api/npmos/crowdsec/decisions" -d "{\"values\": [\"$client_ip\"], \"duration\": \"10m\", \"reason\": \"smoke\"}" \
  | grep -q '"count": *1' || fail "the ban was not added"
wait_page / 403 "test.local for a banned address"
$CURL "$ADMIN/api/npmos/crowdsec/decisions?q=$client_ip" | grep -q '"scenario": *"npmos/manual"' \
  || fail "the ban is not among the decisions"

step "CrowdSec: a host left out by the bouncer lets the banned address in"
api_json -X PUT "$ADMIN/api/npmos/crowdsec/hosts/proxy_host/1" -d '{"bouncer": false}' > /dev/null
wait_page / 200 "test.local left out by the bouncer"
api_json -X PUT "$ADMIN/api/npmos/crowdsec/hosts/proxy_host/1" -d '{"bouncer": true}' > /dev/null
wait_page / 403 "test.local checked by the bouncer again"

step "CrowdSec: unban lets the tester in"
api_json "$ADMIN/api/npmos/crowdsec/decisions/delete" -d "{\"values\": [\"$client_ip\"]}" | grep -q '"deleted": *[1-9]' \
  || fail "the ban was not removed"
wait_page / 200 "test.local after the unban"

step "CrowdSec: AppSec blocks a probe of /.env, its alert becomes a security event"
wait_page /.env 403 "a probe of /.env with AppSec"
for i in $(seq 1 45); do
  $CURL "$ADMIN/api/npmos/events?kind=crowdsec&limit=5" | grep -q '"kind": *"crowdsec"' && break
  [ "$i" = 45 ] && fail "no CrowdSec alert in the events: $($CURL "$ADMIN/api/npmos/events?kind=crowdsec&limit=5")"
  sleep 2
done
# the agents are one list, each row names its agent
$CURL "$ADMIN/api/npmos/events?agent=crowdsec&limit=5" | grep -q '"kind": *"crowdsec"' \
  || fail "the CrowdSec alert is not in the events of the agents"
api_json "$ADMIN/api/npmos/crowdsec/decisions/delete" -d "{\"values\": [\"$client_ip\"]}" > /dev/null || true

if $CURL "$ADMIN/api/npmos/waf" | grep -q '"reachable": *true'; then
  step "CrowdSec: three requests blocked by open-appsec ban the address"
  # the WAF steps above leave test.local in detect-learn: the scenario counts blocked requests only
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/npmos/waf/hosts/1" \
    -d '{"enabled": true, "mode": "prevent-learn", "minimum_confidence": "high"}' > /dev/null
  wait_status "$SQLI" 403 "SQLi is not blocked in prevent-learn again"
  for i in $(seq 1 30); do
    page "$SQLI" > /dev/null
    $CURL "$ADMIN/api/npmos/crowdsec/decisions?q=$client_ip" | grep -q 'npmos/openappsec-prevent' && break
    [ "$i" = 30 ] && fail "blocked requests of open-appsec did not ban: $($CURL "$ADMIN/api/npmos/crowdsec/alerts?limit=5")"
    sleep 2
  done
  wait_page / 403 "test.local for an address banned for its attacks"
  api_json "$ADMIN/api/npmos/crowdsec/decisions/delete" -d "{\"values\": [\"$client_ip\"]}" > /dev/null
  wait_page / 200 "test.local after the unban"
fi

step "CrowdSec: a blocklist file becomes decisions, the allowlist and bad lines are left out"
printf '# smoke\n203.0.113.10\n203.0.113.0/28 range\nnot-an-ip\n2001:db8::10\n' > /tmp/list.txt
list=$($CURL -X POST -H 'Content-Type: text/plain' --data-binary @/tmp/list.txt \
  "$ADMIN/api/npmos/crowdsec/blocklists?name=smoke&duration=1h")
echo "$list" | tr -d ' \n' | grep -q '"count":3' || fail "the blocklist did not make 3 decisions: $list"
$CURL "$ADMIN/api/npmos/crowdsec/decisions?origin=lists" | grep -q '"value": *"203.0.113.0/28"' \
  || fail "the range of the blocklist is not banned"

step "CrowdSec: other nodes take the decisions of this one with its token only"
api_json "$ADMIN/api/npmos/crowdsec/decisions" -d '{"values": ["192.0.2.77"], "duration": "1h"}' > /dev/null
token=$(api_json -X PUT "$ADMIN/api/npmos/crowdsec/share" -d '{"enabled": true}' | tr -d ' \n' \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
[ -n "$token" ] || fail "no token for other nodes"
expect "$(curl -sS -k -o /dev/null -w '%{http_code}' "$ADMIN/api/npmos/crowdsec/public/decisions")" 403 "the export without a token"
export=$(curl -sS -k -H "Authorization: Bearer $token" "$ADMIN/api/npmos/crowdsec/public/decisions")
echo "$export" | grep -q '^192.0.2.77$' || fail "the export has no decision by hand: $export"
echo "$export" | grep -q '203.0.113.10' && fail "the export has the decisions of a blocklist"
node=$(api_json "$ADMIN/api/npmos/crowdsec/blocklists" -d "{\"name\": \"node\", \"source\": \"url\",
  \"url\": \"$ADMIN/api/npmos/crowdsec/public/decisions\", \"token\": \"$token\", \"insecure\": true, \"refresh_minutes\": 60}")
echo "$node" | tr -d ' \n' | grep -q '"error":""' || fail "the decisions of another node were not taken: $node"

step "CrowdSec: a hub item installs from the offline snapshot and is removed again"
api_json --max-time 300 "$ADMIN/api/npmos/crowdsec/hub" \
  -d '{"type": "collections", "name": "crowdsecurity/nextcloud", "action": "install"}' \
  | grep -q 'scenarios/crowdsecurity/nextcloud-bf' || fail "the collection did not install with its scenario"
$CURL "$ADMIN/api/npmos/crowdsec/hub?type=collections&q=nextcloud&installed=true" | grep -q '"status": *"up-to-date"' \
  || fail "the installed collection is not up to date"
api_json --max-time 300 "$ADMIN/api/npmos/crowdsec/hub" \
  -d '{"type": "collections", "name": "crowdsecurity/nextcloud", "action": "remove"}' \
  | grep -q 'collections/crowdsecurity/nextcloud' || fail "the collection was not removed"

step "CrowdSec: the machines and bouncers of the stack cannot be deleted, an unknown one is not found"
for target in machines/localhost bouncers/npmos bouncers/appsec; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' -b "$JAR" -X DELETE "$ADMIN/api/npmos/crowdsec/registry/$target")
  [ "$code" = 400 ] || fail "$target of the stack was not protected: HTTP $code"
done
code=$(curl -sk -o /dev/null -w '%{http_code}' -b "$JAR" -X DELETE "$ADMIN/api/npmos/crowdsec/registry/machines/nope")
[ "$code" = 404 ] || fail "deleting an unknown machine: HTTP $code"

step "GeoIP: the database of CrowdSec gives countries offline, a file that is no database is refused"
$CURL "$ADMIN/api/npmos/system/geoip" | grep -q '"type": *"GeoLite2' || fail "no GeoIP database: $($CURL "$ADMIN/api/npmos/system/geoip")"
code=$(curl -sk -o /dev/null -w '%{http_code}' -b "$JAR" -X POST -H 'Content-Type: application/octet-stream' \
  --data-binary 'not a database' "$ADMIN/api/npmos/system/geoip")
[ "$code" = 400 ] || fail "a broken GeoIP database was accepted: HTTP $code"

step "Migration: a backup of NPM is read and analyzed; the import waits for a new NPMOS"
mig=$(curl -sS --max-time 120 -k -b $JAR -X POST -H 'Content-Type: application/octet-stream' \
  --data-binary @/fixtures/npm-backup.tgz "$ADMIN/api/npmos/system/migration/upload")
echo "$mig" | grep -q '"kind": *"open-appsec-npm"' || fail "the backup was not recognised: $mig"
echo "$mig" | grep -q '"code": *"plain_passwords"' || fail "plain access list passwords not found: $mig"
echo "$mig" | grep -q '"table": *"proxy_host"' || fail "the import is not blocked by existing hosts: $mig"
code=$(curl -sk -o /dev/null -w '%{http_code}' -b "$JAR" -X POST -H 'Content-Type: application/json' -d '{}' \
  "$ADMIN/api/npmos/system/migration/apply")
[ "$code" = 400 ] || fail "the import into an NPMOS with hosts was not refused: HTTP $code"
$CURL -X DELETE "$ADMIN/api/npmos/system/migration" | grep -q '"stage": *"idle"' || fail "the migration was not discarded"

echo "OK: closed-network smoke passed"
