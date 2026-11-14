#!/bin/sh
# Smoke scenarios run inside the closed network against a fresh stack.
# Each phase appends its scenarios here.
set -eu

ADMIN="https://nginxions:81"
HTTP="http://nginxions"
EMAIL="admin@nginxions.test"
PASSWORD="nginxions-airgap-$(date +%s)"
# cookie jar on a volume shared between tester runs (session must survive an nginxions restart)
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
  step "session is still valid after nginxions restart (persistent COOKIE_SECRET)"
  wait_api
  $CURL "$ADMIN/api/users/me" | grep -q '"email": *"admin@nginxions.test"' || fail "session lost after restart"
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

step "disabling a 404 host that does not exist answers 404 and does not crash the backend"
code=$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' -X POST "$ADMIN/api/nginx/dead-hosts/999999/disable")
[ "$code" = 404 ] || fail "disable of a missing 404 host: expected 404, got $code"
sleep 2
$CURL "$ADMIN/api/" | grep -q '"status": *"OK"' || fail "backend is down after disabling a missing 404 host"

step "a ?expand= that is not a relation answers 400, not an internal error (found by ZAP)"
for expand in 'http%3A%2F%2Fwww.google.com%2F' 'nothing' '%5Bowner'; do
  code=$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' "$ADMIN/api/nginx/access-lists?expand=$expand")
  [ "$code" = 400 ] || fail "access lists with ?expand=$expand: expected 400, got $code"
done
code=$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' "$ADMIN/api/nginx/access-lists?expand=owner,items")
[ "$code" = 200 ] || fail "access lists with ?expand=owner,items: expected 200, got $code"

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

step "System → Services: nginxions-control lists the stack: nginxions, openappsec, crowdsec, postgres and nothing more"
services=$($CURL "$ADMIN/api/nginxions/services")
for s in nginxions openappsec postgres; do
  echo "$services" | grep -q "\"service\": *\"$s\"" || fail "service $s is not listed: $services"
done
for s in nginxions-control socket-proxy appsec-agent appsec-shared-storage appsec-tuning-svc; do
  echo "$services" | grep -q "\"service\": *\"$s\"" && fail "service $s is still a container of its own"
done

step "System → Services: service logs are readable"
$CURL "$ADMIN/api/nginxions/services/nginxions/logs?tail=20" | grep -q '"line"' || fail "no nginxions logs"

step "System → Services: an unknown service is not found"
code=$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' -X POST "$ADMIN/api/nginxions/services/socket-proxy/restart")
[ "$code" = 404 ] || fail "restart of an unknown service: expected 404, got $code"

step "System → Services: restart postgres, the backend reconnects"
$CURL -X POST "$ADMIN/api/nginxions/services/postgres/restart" | grep -q '"restarted": *true' || fail "postgres restart failed"
for i in $(seq 1 30); do
  $CURL "$ADMIN/api/users/me" 2>/dev/null | grep -q "$EMAIL" && break
  [ "$i" = 30 ] && fail "backend did not reconnect to postgres"
  sleep 2
done
$CURL "$ADMIN/api/audit-log" | grep -q '"action": *"restarted"' || fail "restart is not in the audit log"

step "System → Services: regenerate nginx config, the proxy host still answers"
$CURL -X POST "$ADMIN/api/nginxions/nginx/regenerate" | grep -q '"regenerated": *true' || fail "regenerate failed"
curl -sS --max-time 10 -H 'Host: test.local' "$HTTP/" | grep -q '^Hostname:' || fail "proxy host is down after regenerate"

step "System → Services: diagnostic archive"
$CURL -o /tmp/diagnostics.zip "$ADMIN/api/nginxions/diagnostics"
[ "$(head -c 2 /tmp/diagnostics.zip)" = PK ] || fail "diagnostic archive is not a zip"

step "WAF: protecting a proxy host generates its rule in local_policy.yaml"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/hosts/1" \
  -d '{"enabled": true, "mode": "prevent-learn", "minimum_confidence": "high"}' > /dev/null
for i in $(seq 1 10); do
  $CURL "$ADMIN/api/nginxions/waf/policy" | grep -q 'name: npm-managed-specific-rule-proxyhost-1\\n *host: test.local\\n' && break
  [ "$i" = 10 ] && fail "no rule for test.local in the policy: $($CURL "$ADMIN/api/nginxions/waf/policy")"
  sleep 1
done
$CURL "$ADMIN/api/nginxions/waf/policy" | grep -q 'mode: prevent-learn' || fail "the rule is not in prevent-learn"

if $CURL "$ADMIN/api/nginxions/waf" | grep -q '"reachable": *true'; then
  step "WAF: open-appsec is on after a clean install (the nginx attachment is loaded by default)"
  $CURL "$ADMIN/api/nginxions/waf" | grep -q '"active": *true' \
    || fail "attachment is not active by default: $($CURL "$ADMIN/api/nginxions/waf")"

  # the switch of the GUI: off, then on again; each restarts nginxions with or without the attachment
  waf_switch() {
    step "WAF: switch open-appsec $2 in the GUI (nginxions restarts)"
    $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf" -d "{\"enabled\": $1, \"apply\": true}" \
      | grep -q '"restarting": *true' || fail "WAF switch did not restart nginxions"
    # nginxions-control answers first, then restarts nginxions (the agent in openappsec keeps running)
    sleep 7
    wait_api
    for i in $(seq 1 30); do
      $CURL "$ADMIN/api/nginxions/waf" | grep -q "\"active\": *$1" && break
      [ "$i" = 30 ] && fail "attachment is not active=$1: $($CURL "$ADMIN/api/nginxions/waf")"
      sleep 2
    done
  }
  waf_switch false off
  waf_switch true on

  step "WAF: the open-appsec agent applies its policy without internet (local-only mode)"
  for i in $(seq 1 90); do
    $CURL "$ADMIN/api/nginxions/waf" | grep -q '"lastPolicyUpdate": *"' && break
    [ "$i" = 90 ] && fail "agent did not apply a policy: $($CURL "$ADMIN/api/nginxions/waf")"
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
  # the agent's model takes "style" for XSS: without the browser headers among its clean headers (its waap.data) every stylesheet of Chrome was refused
  browser=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: test.local' -H 'Accept: text/css,*/*;q=0.1' \
    -H 'Sec-Fetch-Dest: style' -H 'Sec-Fetch-Mode: no-cors' -H 'Sec-Fetch-Site: same-origin' -H 'Priority: u=0' \
    -H 'Sec-Ch-Ua-Mobile: ?0' -H 'Sec-Ch-Ua-Platform: "Linux"' "$HTTP/assets/index.css")
  [ "$browser" = 403 ] && fail "a stylesheet request of a browser was blocked"
  # retried like the checks above: a request handled while the agent restarts a service passes (fail-open)
  for i in $(seq 1 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: test.local' \
      -H 'Sec-Fetch-Dest: <script>alert(document.cookie)</script>' "$HTTP/")" = 403 ] && break
    [ "$i" = 30 ] && fail "an attack in Sec-Fetch-Dest was not blocked"
    sleep 2
  done

  step "WAF: a non-standard HTTP method is blocked (recommended practice: nonValidHttpMethods, read by the agent)"
  for i in $(seq 1 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X ARBITRARY -H 'Host: test.local' "$HTTP/")" = 403 ] && break
    [ "$i" = 30 ] && fail "the method ARBITRARY was not blocked"
    sleep 2
  done

  step "Block page: a refused request gets the page of NginxionS, not the one of the agent"
  for i in $(seq 1 30); do
    page=$(curl -s --max-time 10 -H 'Host: test.local' "$HTTP$SQLI")
    echo "$page" | grep -q 'NginxionS: block page' && break
    [ "$i" = 30 ] && fail "no block page of NginxionS: $(echo "$page" | head -c 300)"
    sleep 2
  done
  echo "$page" | grep -q 'Check Point' && fail "the page of the agent is shown"
  echo "$page" | grep -q '{{ip}}' && fail "the details of the request are not filled in"

  # events of the agent's security log, newest first. The attack is repeated while waiting: the agent
  # restarts its services a few seconds after a start or a new policy, and the event of a request
  # handled just before such a restart can be lost.
  event() {
    for i in $(seq 1 30); do
      status "$SQLI" > /dev/null || true
      $CURL "$ADMIN/api/nginxions/events?important=true&host=test.local" | grep -q "\"action\": *\"$1\"" && return 0
      sleep 2
    done
    fail "no $1 event for test.local in WAF -> Events: $($CURL "$ADMIN/api/nginxions/events?kind=all&limit=5")"
  }

  step "WAF -> Events: the blocked attack is an important event (Prevent)"
  event Prevent

  # Agent settings from the GUI: saving restarts the agent, its entrypoint applies them.
  # $1: JSON body, $2: what is checked
  started() { $CURL "$ADMIN/api/nginxions/services/$1" 2>/dev/null | grep -o '"startedAt": *"[^"]*"'; }
  agent_settings() {
    step "WAF -> Agent: $2"
    nginxions_before=$(started nginxions)
    $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/agent" -d "$1" \
      | grep -q '"restarting": *true' || fail "saving agent settings did not restart the agent"
    # the agent restarts, then nginxions: the API is away for a while (connections are reset)
    for i in $(seq 1 60); do
      agent=$($CURL "$ADMIN/api/nginxions/waf/agent" 2>/dev/null || true)
      echo "$agent" | grep -q '"restartRequired": *false' && break
      [ "$i" = 60 ] && fail "the agent did not apply its settings: $agent"
      sleep 2
    done
    # nginxions-control restarts nginxions once the new agent is up, which can be after the agent already
    # answers: wait for it, or the next request of the test meets nginx without its backend (502)
    for i in $(seq 1 60); do
      now=$(started nginxions || true)
      [ -n "$now" ] && [ "$now" != "$nginxions_before" ] && break
      [ "$i" = 60 ] && fail "nginxions was not restarted after the agent: $now"
      sleep 2
    done
    for i in $(seq 1 60); do
      $CURL "$ADMIN/api/nginxions/waf" 2>/dev/null | grep -q '"reachable": *true' && break
      [ "$i" = 60 ] && fail "the agent did not come back after the restart: $($CURL "$ADMIN/api/nginxions/waf")"
      sleep 2
    done
    for i in $(seq 1 60); do
      [ "$(status "$SQLI")" = 403 ] && break
      [ "$i" = 60 ] && fail "SQLi is not blocked after the agent's restart"
      sleep 2
    done
    since=$(date -u +%Y-%m-%dT%H:%M:%S)
    for i in $(seq 1 30); do
      # nginxions restarts after the agent, possibly only now: a refused connection (curl 7) is retried, not fatal
      status "$XSS" > /dev/null || true
      # an event newer than the restart (times are ISO, compared as text)
      $CURL "$ADMIN/api/nginxions/events?important=true&host=test.local&limit=1" \
        | grep -o '"time": *"[^"]*"' | cut -d'"' -f4 | awk -v s="$since" '$0 >= s {f=1} END {exit !f}' && return 0
      sleep 2
    done
    fail "attacks after the agent's restart are not in WAF -> Events: $($CURL "$ADMIN/api/nginxions/events?kind=all&limit=3")"
  }

  agent_settings '{"fail_open": {"enabled": true, "timeout_ms": 100}}' \
    "fail-open timeout from the GUI is applied at the agent's restart, attacks are still blocked and logged"
  agent_settings '{"fail_open": {"enabled": true, "timeout_ms": 50}}' \
    "a second change is applied the same way"

  # applying agent settings restarts the agent process in openappsec, then nginxions: without the restart of nginxions
  # the nginx attachment kept its IPC with the old agent and every request waited for it (about 1-2 s)
  step "WAF -> Agent: after the agent's restart requests are not held up"
  slow=0
  for i in $(seq 1 10); do
    t=$(curl -s -o /dev/null -w '%{time_total}' --max-time 10 -H 'Host: test.local' "$HTTP/")
    awk -v t="$t" 'BEGIN {exit !(t > 0.5)}' && slow=$((slow + 1))
  done
  [ "$slow" -le 1 ] || fail "$slow of 10 requests took more than 0.5 s after the agent's restart"
  t=$($CURL -o /dev/null -w '%{time_total}' "$ADMIN/api/")
  awk -v t="$t" 'BEGIN {exit !(t > 0.5)}' && fail "the interface took $t s: it must not wait for the agent"

  step "WAF -> Agent: the metrics of the agent (its prometheus service) are read"
  metrics=""
  for i in $(seq 1 30); do
    metrics=$($CURL "$ADMIN/api/nginxions/waf/agent/metrics" | tr -d ' \n')
    echo "$metrics" | grep -q '"reachable":true' && break
    [ "$i" = 30 ] && fail "the metrics service of the agent does not answer: $(echo "$metrics" | head -c 300)"
    sleep 4
  done
  echo "    metrics of the agent: $(echo "$metrics" | grep -o '"name":"[^"]*"' | wc -l)"

  wait_status() {
    for i in $(seq 1 60); do
      [ "$(status "$1")" = "$2" ] && return 0
      sleep 2
    done
    fail "$3 (last status $(status "$1"))"
  }
  # the same, three times in a row: while the agent reloads its policy, fail-open lets a blocked request through once
  wait_status_stable() {
    for i in $(seq 1 60); do
      [ "$(status "$1")" = "$2" ] && [ "$(status "$1")" = "$2" ] && [ "$(status "$1")" = "$2" ] && return 0
      sleep 2
    done
    fail "$3 (last status $(status "$1"))"
  }

  step "WAF -> Policy (expert): an exception for the tester's IP lets the attack through"
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/policy/custom" -d "{
    \"content\": \"exceptions:\\n  - name: smoke-trusted\\n    action: accept\\n    condition:\\n      - key: sourceIp\\n        value: $client_ip\\npolicies:\\n  default:\\n    exceptions:\\n      - smoke-trusted\\n\",
    \"comment\": \"smoke\"}" > /dev/null
  $CURL "$ADMIN/api/nginxions/waf/policy" | grep -q 'name: smoke-trusted' || fail "the exception is not in the policy"
  wait_status_stable "$SQLI" 200 "SQLi from the trusted IP is still blocked"

  step "WAF -> Policy (expert): without the fragment (a new empty version) the attack is blocked again"
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/policy/custom" \
    -d '{"content": "", "comment": "smoke: empty"}' > /dev/null
  for i in $(seq 1 60); do
    [ "$(status "$SQLI")" = 403 ] && break
    [ "$i" = 60 ] && fail "SQLi is not blocked after the exception was removed"
    sleep 2
  done
  $CURL "$ADMIN/api/nginxions/waf/policy/custom" | grep -q '"comment": *"smoke: empty"' || fail "versions are not listed"

  # WAF -> Policy (phase 5): objects of the policy through the API of the GUI
  json() { tr -d ' \n'; }
  object_id() {
    $CURL "$ADMIN/api/nginxions/waf/policy/objects" | json \
      | grep -o "\"id\":[0-9]*,[^{}]*\"kind\":\"$1\",\"name\":\"$2\"" | head -1 | sed 's/"id":\([0-9]*\).*/\1/'
  }
  new_id() { json | grep -o '^{"id":[0-9]*' | grep -o '[0-9]*$'; }
  last_version() { $CURL "$ADMIN/api/nginxions/waf/policy/versions" | json | grep -o '^\[{"id":[0-9]*' | grep -o '[0-9]*$'; }
  post_json() { $CURL -X "$1" -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/policy$2" -d "$3"; }
  step "WAF -> Policy: an exception object in the default policy lets the attack through, a rollback blocks it again"
  recommended=$(object_id threat_prevention nginxions-recommended)
  trigger=$(object_id log_trigger nginxions-log)
  response=$(object_id custom_response nginxions-403)
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
  # the dry run on recent events: the attacks of the tester blocked so far would pass with the exception
  preview=$(post_json POST /preview "{\"policy\": $default_policy, \"exceptions\": [$exception]}, \"simulate\": \"24h\"}" | json)
  echo "$preview" | grep -q '"toPass":[1-9]' \
    || fail "the dry run does not let the blocked attacks of the tester through: $(echo "$preview" | grep -o '"simulation":{[^]]*' | head -c 400)"
  post_json PUT /default "$default_policy, \"exceptions\": [$exception]}" > /dev/null
  $CURL "$ADMIN/api/nginxions/waf/policy" | grep -q -- "value: $client_ip" || fail "the exception is not in local_policy.yaml"
  wait_status_stable "$SQLI" 200 "SQLi from an IP of the exception is still blocked"
  [ "$($CURL -o /dev/null -w "%{http_code}" -X DELETE "$ADMIN/api/nginxions/waf/policy/objects/$exception" 2>/dev/null || true)" = 400 ] \
    || fail "an object in use was deleted"
  post_json POST "/versions/$before/rollback" "" > /dev/null
  wait_status "$SQLI" 403 "SQLi is not blocked after the rollback"

  step "WAF -> Policy: local_policy.yaml is v1beta2; a rate limit of the host limits requests"
  limit=$(post_json POST /objects '{"kind": "access_control", "name": "smoke-limit",
    "spec": {"rateLimit": {"overrideMode": "prevent", "rules": [{"uri": "/smoke-rate", "limit": 3, "unit": "minute"}]}}}' \
    | new_id)
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/hosts/1" -d "{\"enabled\": true,
    \"mode\": \"prevent-learn\", \"minimum_confidence\": \"high\", \"objects\": {\"accessControlPractices\": [$limit]}}" > /dev/null
  $CURL "$ADMIN/api/nginxions/waf/policy" | grep -q '"format": *"v1beta2"' \
    || fail "the policy is not v1beta2: $($CURL "$ADMIN/api/nginxions/waf/policy" | head -c 400)"
  # the path holds no word the model reads as an attack ("limit" is an SQL keyword): a 403 here is the rate limit's
  limited=""
  for i in $(seq 1 60); do
    for _ in 1 2 3 4 5 6; do
      [ "$(status /smoke-rate)" = 403 ] && limited=1
    done
    [ -n "$limited" ] && break
    [ "$i" = 60 ] && fail "requests over the rate limit are not blocked (statuses: $(for _ in 1 2 3 4 5 6; do printf '%s ' "$(status /smoke-rate)"; done))"
    sleep 2
  done
  [ "$(status /)" = 200 ] || fail "a path without a rate limit is blocked"
  # a rate limit lets the path through again once its minute is over (no request in between: each one blocked
  # renews the block); a refusal of the path itself would not
  sleep 65
  [ "$(status /smoke-rate)" = 200 ] || fail "the path stays blocked after the minute of the rate limit"
  wait_status "$SQLI" 403 "SQLi is not blocked with the rate limit of the host"
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/hosts/1" \
    -d '{"enabled": true, "mode": "prevent-learn", "minimum_confidence": "high", "objects": null}' > /dev/null

  host_objects() {
    $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/hosts/1" -d "{\"enabled\": true,
      \"mode\": \"prevent-learn\", \"minimum_confidence\": \"high\", \"objects\": $1}" > /dev/null
  }
  step "WAF -> Policy: every exception of a rule applies, not only the first"
  # the agent took the first exception of a rule only: the second one, for the tester's IP, had no effect
  other=$(post_json POST /objects '{"kind": "exception", "name": "smoke-other",
    "spec": {"action": "accept", "condition": [{"key": "sourceIp", "value": "192.0.2.7"}]}}' | new_id)
  mine=$(post_json POST /objects "{\"kind\": \"exception\", \"name\": \"smoke-mine\",
    \"spec\": {\"action\": \"accept\", \"condition\": [{\"key\": \"sourceIp\", \"value\": \"$client_ip\"}]}}" | new_id)
  [ -n "$other" ] && [ -n "$mine" ] || fail "the exceptions were not created"
  host_objects "{\"accessControlPractices\": [$limit], \"exceptions\": [$other, $mine]}"
  wait_status_stable "$SQLI" 200 "the second exception of a rule does not let the attack through"
  host_objects null
  wait_status "$SQLI" 403 "SQLi is not blocked once the exceptions are gone"

  step "WAF -> Policy: x-nginxions conditions of an exception: not-in and a header name"
  # every source but 192.0.2.7: the tester's attack passes
  not_in=$(post_json POST /objects '{"kind": "exception", "name": "smoke-not-in",
    "spec": {"action": "accept", "condition": [{"key": "sourceIp", "op": "not-in", "value": "192.0.2.7"}]}}' | new_id)
  # a request with the header is dropped, even a normal one
  by_header=$(post_json POST /objects '{"kind": "exception", "name": "smoke-header",
    "spec": {"action": "drop", "condition": [{"key": "headerName", "value": "x-smoke-drop"}]}}' | new_id)
  [ -n "$not_in" ] && [ -n "$by_header" ] || fail "the exceptions of x-nginxions were not created"
  host_objects "{\"exceptions\": [$not_in]}"
  wait_status_stable "$SQLI" 200 "an exception for every source but another one does not let the attack through"
  host_objects "{\"exceptions\": [$by_header]}"
  for i in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: test.local' -H 'X-Smoke-Drop: 1' "$HTTP/")" = 403 ] \
      && break
    [ "$i" = 60 ] && fail "a request with the header of a drop exception is not dropped"
    sleep 2
  done
  [ "$(status /)" = 200 ] || fail "a request without the header of a drop exception is dropped"
  host_objects null
  wait_status "$SQLI" 403 "SQLi is not blocked once the exceptions of x-nginxions are gone"

  step "WAF -> Policy: the IPS of a practice blocks a known vulnerability (signatures of NginxionS, CrowdSec virtual patching)"
  # PHPUnit eval-stdin.php (CVE-2017-9841, vpatch-CVE-2017-9841): a plain GET, no payload the ML model of the WAF reads as
  # an attack; the IPS of the agent had no signatures without the Check Point cloud
  PHPUNIT=/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
  wait_status_stable "$PHPUNIT" 200 "the path of PHPUnit is blocked without the IPS"
  ips=$(post_json POST /objects '{"kind": "threat_prevention", "name": "smoke-ips",
    "spec": {"practiceMode": "inherited", "webAttacks": {"overrideMode": "inherited", "minimumConfidence": "high"},
    "intrusionPrevention": {"overrideMode": "prevent", "minSeverityLevel": "medium", "minCveYear": 2010,
    "highConfidenceEventAction": "prevent", "mediumConfidenceEventAction": "prevent", "lowConfidenceEventAction": "detect"}}}' \
    | new_id)
  [ -n "$ips" ] || fail "the practice with the IPS was not created"
  host_objects "{\"threatPreventionPractices\": [$ips]}"
  wait_status "$PHPUNIT" 403 "the IPS does not block CVE-2017-9841"
  [ "$(status /)" = 200 ] || fail "the IPS blocks a normal request"
  for i in $(seq 1 30); do
    $CURL "$ADMIN/api/nginxions/events?kind=all&host=test.local&q=CVE-2017-9841&limit=1" | grep -q '"incident_type": *"IPS"' \
      && break
    [ "$i" = 30 ] && fail "no event of the IPS in WAF -> Events: $($CURL "$ADMIN/api/nginxions/events?kind=all&limit=3" | head -c 600)"
    sleep 2
  done
  # the year of a signature counts: CVE-2017 is older than 2018
  post_json PUT "/objects/$ips" '{"kind": "threat_prevention", "name": "smoke-ips", "spec": {"practiceMode": "inherited",
    "webAttacks": {"overrideMode": "inherited", "minimumConfidence": "high"},
    "intrusionPrevention": {"overrideMode": "prevent", "minCveYear": 2018}}}' > /dev/null
  wait_status_stable "$PHPUNIT" 200 "a signature of a CVE older than minCveYear still blocks"
  host_objects null
  wait_status_stable "$PHPUNIT" 200 "the path of PHPUnit is blocked once the IPS is off"
  wait_status "$SQLI" 403 "SQLi is not blocked once the practice with the IPS is gone"

  step "WAF -> Policy: a custom response «response code only» answers with its own code"
  code406=$(post_json POST /objects '{"kind": "custom_response", "name": "smoke-406",
    "spec": {"mode": "response-code-only", "httpResponseCode": 406}}' | new_id)
  [ -n "$code406" ] || fail "the custom response was not created"
  host_objects "{\"customResponse\": $code406}"
  wait_status "$SQLI" 406 "the attack is not answered with the code of the custom response"
  host_objects null
  wait_status "$SQLI" 403 "SQLi is not answered with 403 again"

  step "WAF -> Policy: a custom response «block page» shows its own title and text, nothing of a vendor"
  page406=$(post_json POST /objects '{"kind": "custom_response", "name": "smoke-page",
    "spec": {"mode": "block-page", "httpResponseCode": 406, "messageTitle": "Smoke title",
    "messageBody": "Smoke text of the page"}}' | new_id)
  [ -n "$page406" ] || fail "the custom response with a page was not created"
  host_objects "{\"customResponse\": $page406}"
  # the handlers of the agent take a new policy one after another: a request may still meet the previous response
  # (403) for a while, so the page and its code are waited for together, from one request, three times in a row
  hits=0
  for i in $(seq 1 60); do
    body=$(curl -s --max-time 10 -w ' HTTPCODE=%{http_code}' -H 'Host: test.local' "$HTTP$SQLI")
    code=${body##* HTTPCODE=}
    body=${body% HTTPCODE=*}
    if [ "$code" = 406 ] && echo "$body" | grep -q "Smoke title"; then hits=$((hits + 1)); else hits=0; fi
    [ "$hits" = 3 ] && break
    [ "$i" = 60 ] && fail "the custom response is not a page with its code 406 (status $code): $(echo "$body" | head -c 300)"
    sleep 1
  done
  echo "$body" | grep -q "Smoke text of the page" || fail "the text of the custom response is not on the page"
  echo "$body" | grep -q "Incident Id" || fail "the incident ID is not on the page"
  echo "$body" | grep -qi "check point\|openappsec" && fail "the page names a vendor: $(echo "$body" | head -c 300)"
  [ "${#body}" -lt 4000 ] || fail "the page of the WAF is ${#body} bytes (the page of Check Point was 278 KB)"
  host_objects null
  wait_status "$SQLI" 403 "SQLi is not answered with 403 again"

  step "WAF -> Policy: a rate limit rule has its own conditions and action, answered with the response of the rule"
  # one practice, three rules: the tester's IP is limited on /smoke-mine; another IP only on /smoke-other; detect on
  # /smoke-detect logs and lets through (the action and the conditions of a rule were not read by the agent)
  rules=$(post_json POST /objects "{\"kind\": \"access_control\", \"name\": \"smoke-rules\",
    \"spec\": {\"rateLimit\": {\"overrideMode\": \"prevent\", \"rules\": [
      {\"uri\": \"/smoke-mine\", \"limit\": 2, \"unit\": \"minute\",
       \"condition\": [{\"key\": \"sourceIp\", \"value\": \"$client_ip\"}]},
      {\"uri\": \"/smoke-other\", \"limit\": 2, \"unit\": \"minute\",
       \"condition\": [{\"key\": \"sourceIp\", \"value\": \"192.0.2.99\"}]},
      {\"uri\": \"/smoke-detect\", \"limit\": 2, \"unit\": \"minute\", \"action\": \"detect\"}]}}}" | new_id)
  [ -n "$rules" ] || fail "the practice with rate limit rules was not created"
  host_objects "{\"accessControlPractices\": [$rules], \"customResponse\": $code406}"
  limited=""
  for i in $(seq 1 60); do
    for _ in 1 2 3 4 5; do
      [ "$(status /smoke-mine)" = 406 ] && limited=1
    done
    [ -n "$limited" ] && break
    [ "$i" = 60 ] && fail "the rule for the tester's IP does not limit, or not with the response of the rule (406)"
    sleep 2
  done
  for _ in 1 2 3 4 5 6; do
    [ "$(status /smoke-other)" = 200 ] || fail "a rule for another IP limits the tester"
    [ "$(status /smoke-detect)" = 200 ] || fail "a rule with the action detect blocks"
  done
  host_objects null
  wait_status "$SQLI" 403 "SQLi is not answered with 403 again"

  step "WAF -> Policy: a custom response «redirect» sends the attack to its URL with the ID of the event"
  redirect=$(post_json POST /objects '{"kind": "custom_response", "name": "smoke-redirect",
    "spec": {"mode": "redirect", "redirectUrl": "https://help.example.com/blocked?from=waf", "redirectAddXEventId": true}}' | new_id)
  [ -n "$redirect" ] || fail "the redirect response was not created"
  host_objects "{\"customResponse\": $redirect}"
  location=""
  for i in $(seq 1 60); do
    location=$(curl -s -o /dev/null -D - --max-time 10 -H 'Host: test.local' "$HTTP$SQLI" | tr -d '\r' \
      | sed -n 's/^[Ll]ocation: //p')
    case "$location" in https://help.example.com/blocked\?from=waf\&event-id=*) break ;; esac
    [ "$i" = 60 ] && fail "the attack is not redirected with the ID of the event (status $(status "$SQLI"), location '$location')"
    sleep 2
  done
  host_objects null
  wait_status "$SQLI" 403 "SQLi is not answered with 403 again"

  step "WAF -> Learning: a trial of blocking on a detecting host reports what it would block, then switches it"
  trial() { $CURL -X "$1" -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/hosts/1/trial" ${2:+-d "$2"}; }
  [ "$($CURL -o /dev/null -w "%{http_code}" -X POST -H 'Content-Type: application/json' \
    "$ADMIN/api/nginxions/waf/hosts/1/trial" -d '{"hours": 1}' 2>/dev/null || true)" = 400 ] \
    || fail "a trial was started on a host that blocks already"
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/hosts/1" \
    -d '{"enabled": true, "mode": "detect-learn", "minimum_confidence": "high"}' > /dev/null
  wait_status_stable "$SQLI" 200 "SQLi is still blocked in detect mode"
  trial POST '{"hours": 1}' | json | grep -q '"state":"running"' || fail "the trial did not start"
  report=""
  for i in $(seq 1 30); do
    status "$SQLI" > /dev/null
    report=$(trial GET | json)
    echo "$report" | grep -q '"toBlock":[1-9]' && break
    [ "$i" = 30 ] && fail "the trial does not report the attacks blocking would block: $(echo "$report" | head -c 400)"
    sleep 4
  done
  $CURL "$ADMIN/api/nginxions/learning/hosts" | json | grep -q '"trial":{"id"' || fail "Learning does not show the trial"
  trial PUT '{"enable": true}' | json | grep -q '"outcome":"enabled"' || fail "the trial was not closed by switching"
  $CURL "$ADMIN/api/nginxions/waf/hosts/1" | json | grep -q '"mode":"prevent-learn"' \
    || fail "the host was not switched to blocking by the trial"
  wait_status "$SQLI" 403 "SQLi is not blocked after the trial switched the host"

  step "WAF -> Policy: the v1beta2 example of open-appsec is imported and applied by the agent"
  applied_at() { $CURL "$ADMIN/api/nginxions/waf" | json | grep -o '"lastPolicyUpdate":"[^"]*"'; }
  before=$(last_version)
  previous=$(applied_at)
  example=$(sed 's/\\/\\\\/g; s/"/\\"/g' /examples/v1beta2-example.yaml | awk '{printf "%s\\n", $0}')
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
    key=$($CURL "$ADMIN/api/nginxions/learning/queue?period=24h&host=1&reason=blocked&suggestions=0" \
      | grep -o '"key": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{32\}' || true)
    [ -n "$key" ] && break
    [ "$i" = 30 ] && fail "no blocked group for test.local: $($CURL "$ADMIN/api/nginxions/learning/queue?period=24h")"
    status "$SQLI" > /dev/null || true
    sleep 2
  done

  step "Learning: what the agent learned on the host is read through nginxions-control"
  learned=$($CURL "$ADMIN/api/nginxions/learning/hosts/1/learned" | json)
  echo "$learned" | grep -q '"assets":\[' || fail "what the agent learned is not read: $(echo "$learned" | head -c 400)"
  echo "$learned" | grep -q 'nginxions-control' && fail "nginxions-control does not read what the agent learned: $(echo "$learned" | head -c 400)"

  step "Learning: labelled legitimate with an exception, the attack passes at once; undo blocks it again"
  label=$($CURL -H 'Content-Type: application/json' "$ADMIN/api/nginxions/learning/labels" -d "{\"key\": \"$key\", \"decision\": \"benign\",
    \"scopes\": [{\"type\": \"parameterName\", \"value\": \"id\"}], \"exception\": true, \"ttl_days\": 1}")
  label_id=$(echo "$label" | grep -o '"id": *[0-9]*' | head -1 | grep -o '[0-9]*$')
  # decisions.data of the assets of the host is written in the shared storage, where the agent reads it
  echo "$label" | grep -q '"syncError": *""' || fail "the label was not written for the agent: $label"
  echo "$label" | grep -q '"syncedOn": *"' || fail "the label was not written for the agent: $label"
  $CURL "$ADMIN/api/nginxions/learning/queue?period=24h&host=1&suggestions=0" | grep -q "\"$key\"" \
    && fail "the labelled group is still in the queue"
  # the exception reaches the policy a moment later (debounced generation); while the agent reloads after the
  # rollback above, fail-open (50 ms) lets the attack through on its own, so 200 alone proves nothing yet
  for i in $(seq 1 30); do
    $CURL "$ADMIN/api/nginxions/waf/policy" | grep -q "nginxions-learn-$label_id" && break
    [ "$i" = 30 ] && fail "no exception of the label in the policy"
    sleep 1
  done
  wait_status_stable "$SQLI" 200 "SQLi labelled legitimate is still blocked"
  $CURL -X DELETE "$ADMIN/api/nginxions/learning/labels/$label_id" | grep -q '"ok": *true' || fail "the label was not undone"
  wait_status "$SQLI" 403 "SQLi is not blocked after the label was undone"
  $CURL "$ADMIN/api/nginxions/learning/labels?active=0" | grep -q '"undoneOn": *"' || fail "the undone label is not in the history"

  step "Learning: a snapshot of what the agent learned is taken, downloaded, uploaded and restored (the agent restarts)"
  snapshot=$($CURL -X POST "$ADMIN/api/nginxions/learning/snapshots" | tr -d ' \n')
  snapshot_id=$(echo "$snapshot" | grep -o '"id":"[0-9TZ]*-[0-9a-f]*"' | head -1 | cut -d'"' -f4)
  [ -n "$snapshot_id" ] || fail "no snapshot was taken: $(echo "$snapshot" | head -c 400)"
  echo "$snapshot" | grep -q '"reason":"manual"' || fail "the snapshot is not a manual one: $(echo "$snapshot" | head -c 400)"
  $CURL -o /tmp/learning.json.gz "$ADMIN/api/nginxions/learning/snapshots/$snapshot_id/download"
  [ "$(od -An -tx1 -N2 /tmp/learning.json.gz | tr -d ' ')" = 1f8b ] || fail "the downloaded snapshot is not gzip"
  uploaded=$($CURL -X POST -H 'Content-Type: application/octet-stream' --data-binary @/tmp/learning.json.gz \
    "$ADMIN/api/nginxions/learning/snapshots/upload" | tr -d ' \n')
  uploaded_id=$(echo "$uploaded" | grep -o '"id":"[0-9TZ]*-[0-9a-f]*"' | head -1 | cut -d'"' -f4)
  echo "$uploaded" | grep -q '"reason":"import"' || fail "the snapshot was not uploaded: $(echo "$uploaded" | head -c 400)"
  # a file that is not a snapshot is refused
  [ "$(printf 'nope' | curl -s -k -o /dev/null -w '%{http_code}' -b "$JAR" -X POST --data-binary @- \
    -H 'Content-Type: application/octet-stream' "$ADMIN/api/nginxions/learning/snapshots/upload" || true)" = 400 ] \
    || fail "a file that is not a snapshot was accepted"
  nginxions_before=$(started nginxions)
  $CURL -X POST "$ADMIN/api/nginxions/learning/snapshots/$uploaded_id/restore" | grep -q '"restarting": *true' \
    || fail "the snapshot was not restored"
  # the agent restarts with the snapshot in place, then nginxions: the API is away for a while
  for i in $(seq 1 90); do
    now=$(started nginxions 2>/dev/null || true)
    [ -n "$now" ] && [ "$now" != "$nginxions_before" ] && break
    [ "$i" = 90 ] && fail "nginxions was not restarted after the restore of the snapshot"
    sleep 2
  done
  for i in $(seq 1 60); do
    $CURL "$ADMIN/api/nginxions/waf" 2>/dev/null | grep -q '"reachable": *true' && break
    [ "$i" = 60 ] && fail "the agent did not come back after the restore: $($CURL "$ADMIN/api/nginxions/waf")"
    sleep 2
  done
  wait_status "$SQLI" 403 "SQLi is not blocked after the restore of a snapshot of learning"
  snapshots=$($CURL "$ADMIN/api/nginxions/learning/snapshots" | tr -d ' \n')
  echo "$snapshots" | grep -q '"reason":"before-restore"' || fail "the state before the restore was not kept: $(echo "$snapshots" | head -c 600)"
  echo "$snapshots" | grep -q '"restoredOn":"' || fail "the restored snapshot is not marked: $(echo "$snapshots" | head -c 600)"
  $CURL "$ADMIN/api/nginxions/learning/hosts/1/learned" | grep -q '"assets"' || fail "what the agent learned is not read after the restore"

  step "WAF: detect-learn lets attacks through"
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/hosts/1" \
    -d '{"enabled": true, "mode": "detect-learn", "minimum_confidence": "high"}' > /dev/null
  wait_status_stable "$SQLI" 200 "SQLi is still blocked in detect-learn"

  step "WAF -> Events: the detected attack is an important event (Detect)"
  event Detect
else
  echo "    (agent not running, WAF scenarios skipped)"
fi

# --- phase 2 ---

step "hosts: the upstream of test.local answers, a dead one does not"
$CURL "$ADMIN/api/nginxions/hosts/upstreams" | tr -d ' \n' | grep -q '"object_id":1,"host":"test-upstream","port":80,"ok":true' \
  || fail "upstream check of test.local: $($CURL "$ADMIN/api/nginxions/hosts/upstreams")"
$CURL -H 'Content-Type: application/json' "$ADMIN/api/nginx/proxy-hosts" -d '{
  "domain_names": ["dead-upstream.local"], "forward_scheme": "http",
  "forward_host": "127.0.0.1", "forward_port": "9"
}' > /dev/null
$CURL "$ADMIN/api/nginxions/hosts/upstreams" | tr -d ' \n' | grep -q '"port":9,"ok":false' \
  || fail "a closed port is reported as reachable: $($CURL "$ADMIN/api/nginxions/hosts/upstreams")"

step "error pages: the 502 of a dead upstream is the page of NginxionS, not the bare page of nginx"
page=""
for i in $(seq 1 15); do
  page=$(curl -sS --max-time 10 -H 'Host: dead-upstream.local' "$HTTP/" || true)
  echo "$page" | grep -q 'The site does not answer' && break
  [ "$i" = 15 ] && fail "502 of a dead upstream: $(echo "$page" | head -c 300)"
  sleep 1
done
echo "$page" | grep -q 'Сайт не отвечает' || fail "502: no Russian text"
echo "$page" | grep -q 'nginx</center>' && fail "502: the bare page of nginx"

step "hosts: who changed test.local and when (audit log)"
$CURL "$ADMIN/api/nginxions/hosts/changes" | tr -d ' \n' | grep -q '"type":"proxy-host","object_id":1,' \
  || fail "no last change of test.local: $($CURL "$ADMIN/api/nginxions/hosts/changes")"
$CURL "$ADMIN/api/nginxions/hosts/changes/proxy-host/1" | grep -q '"action": *"created"' \
  || fail "the history of test.local has no creation: $($CURL "$ADMIN/api/nginxions/hosts/changes/proxy-host/1")"

host_code() { h=$1; shift; curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -H "Host: $h" "$@" "$HTTP$PATH_"; }
host_location() { curl -sS --max-time 10 -o /dev/null -D - -H "Host: $1" "$HTTP$2" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p'; }
new_json() { $CURL -H 'Content-Type: application/json' "$@"; }
id_of() { tr -d ' \n' | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*$'; }
want() { [ "$1" = "$2" ] || fail "$3: expected $2, got $1"; }

step "redirects: every code sends Location with the path (300 too), the scheme «auto» of the old form keeps the scheme"
for code in 300 301 302 303 307 308; do
  new_json "$ADMIN/api/nginx/redirection-hosts" -d "{\"domain_names\": [\"r$code.local\"], \"forward_scheme\": \"https\",
    \"forward_domain_name\": \"target.local\", \"forward_http_code\": $code, \"preserve_path\": true, \"meta\": {}}" > /dev/null
done
new_json "$ADMIN/api/nginx/redirection-hosts" -d '{"domain_names": ["rauto.local"], "forward_scheme": "auto",
  "forward_domain_name": "target.local", "forward_http_code": 302, "preserve_path": true, "meta": {}}' > /dev/null
sleep 2
for code in 300 301 302 303 307 308; do
  PATH_='/a/b?c=1'; got=$(host_code "r$code.local")
  [ "$got" = "$code" ] || fail "redirect $code answered $got"
  loc=$(host_location "r$code.local" "/a/b?c=1")
  [ "$loc" = "https://target.local/a/b?c=1" ] || fail "redirect $code: Location '$loc'"
done
loc=$(host_location rauto.local /p)
[ "$loc" = "http://target.local/p" ] || fail "redirect with the scheme auto: Location '$loc' (not auto://)"

step "ACME servers: a default one at the start, presets, lego in the image; the TLS CA needs lego"
servers=$($CURL "$ADMIN/api/nginxions/acme/servers")
echo "$servers" | tr -d ' \n' | grep -q '"is_default":true' || fail "no default ACME server: $servers"
echo "$servers" | grep -q '"tlscc-stage"' || fail "the presets have no TLS CA: $(echo "$servers" | head -c 300)"
# the codes come from `lego dnshelp`: lego is in the image and runs
$CURL "$ADMIN/api/nginxions/acme/lego/dns-providers" | grep -q '"rfc2136"' || fail "lego does not list its DNS providers"
got=$(curl -sk -o /dev/null -w '%{http_code}' -b "$JAR" -H 'Content-Type: application/json' "$ADMIN/api/nginxions/acme/servers" \
  -d '{"preset": "tlscc-stage", "client": "certbot"}')
[ "$got" = 400 ] || fail "the TLS CA with certbot answered $got (certbot cannot register there)"
own=$(new_json "$ADMIN/api/nginxions/acme/servers" -d '{"name": "smoke own", "directory": "https://ca.internal/acme/directory",
  "client": "lego", "eab_kid": "kid", "eab_hmac_key": "smoke-hmac-secret", "email": "ops@example.com"}')
echo "$own" | grep -q 'smoke-hmac-secret' && fail "the EAB key is returned by the API"
own_id=$(echo "$own" | id_of)
$CURL -X DELETE "$ADMIN/api/nginxions/acme/servers/$own_id" > /dev/null || fail "the ACME server is not removed"

step "ACME HTTP-01: the challenge of a domain without a host is answered over HTTP, not sent to HTTPS"
PATH_=/.well-known/acme-challenge/missing; got=$(host_code no-host.local)
[ "$got" = 404 ] || fail "the challenge path answered $got (a 301 sends the ACME server to the dummy certificate)"
PATH_=/x; got=$(host_code no-host.local)
[ "$got" = 301 ] || fail "other paths of HTTP: expected 301 to HTTPS, got $got"
curl -sSk --max-time 10 -H 'Host: no-host.local' https://nginxions/ \
  | grep -q 'NginxionS is running' || fail "the default page is not the page of NginxionS"

step "default page «no answer» (444): an unknown host gets nothing, the ACME challenge still answers"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/settings/default-site" -d '{"value": "444", "meta": {}}' > /dev/null
sleep 2
rc=0; curl -sS --max-time 10 -o /dev/null -H 'Host: no-host.local' "$HTTP/" 2>/dev/null || rc=$?
[ "$rc" = 52 ] || [ "$rc" = 56 ] || fail "444: curl exit code $rc (expected an empty reply)"
PATH_=/.well-known/acme-challenge/missing; got=$(host_code no-host.local)
[ "$got" = 404 ] || fail "444: the challenge path answered $got"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/settings/default-site" \
  -d '{"value": "congratulations", "meta": {}}' > /dev/null

step "streams: TCP port to the upstream; a second stream on a busy port and the ports of NginxionS are refused"
stream_body() { echo "{\"incoming_port\": \"$1\", \"forwarding_host\": \"test-upstream\", \"forwarding_port\": 80,
  \"tcp_forwarding\": true, \"udp_forwarding\": false, \"meta\": {}}"; }
sid=$(new_json "$ADMIN/api/nginx/streams" -d "$(stream_body 2222)" | id_of)
for i in $(seq 1 10); do
  curl -sS --max-time 5 http://nginxions:2222/ 2>/dev/null | grep -q '^Hostname:' && break
  [ "$i" = 10 ] && fail "the stream on 2222 does not answer"
  sleep 1
done
for port in 2222 2220-2230 443 81; do
  code=$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
    "$ADMIN/api/nginx/streams" -d "$(stream_body $port)")
  [ "$code" = 400 ] || fail "a stream on the busy port $port: expected 400, got $code"
done
$CURL -X DELETE "$ADMIN/api/nginx/streams/$sid" > /dev/null

step "access lists: Basic Auth asks for the login, an IP list lets in the allowed address and refuses another"
acl_host() { # domain, list id
  new_json "$ADMIN/api/nginx/proxy-hosts" -d "{\"domain_names\": [\"$1\"], \"forward_scheme\": \"http\",
    \"forward_host\": \"test-upstream\", \"forward_port\": 80, \"npmplus_access_list_type\": \"custom\",
    \"npmplus_access_list_ids\": [$2]}" > /dev/null
}
basic_id=$(new_json "$ADMIN/api/nginx/access-lists" -d '{"name": "smoke basic", "satisfy_any": false, "pass_auth": false,
  "items": [{"username": "alice", "password": "wonderland1"}], "clients": []}' | id_of)
allow_id=$(new_json "$ADMIN/api/nginx/access-lists" -d "{\"name\": \"smoke allow\", \"satisfy_any\": false,
  \"pass_auth\": false, \"items\": [], \"clients\": [{\"address\": \"$client_ip\", \"directive\": \"allow\"},
  {\"address\": \"all\", \"directive\": \"deny\"}]}" | id_of)
deny_id=$(new_json "$ADMIN/api/nginx/access-lists" -d "{\"name\": \"smoke deny\", \"satisfy_any\": false,
  \"pass_auth\": false, \"items\": [], \"clients\": [{\"address\": \"$client_ip\", \"directive\": \"deny\"}]}" | id_of)
acl_host basic.local "$basic_id"; acl_host ip-allow.local "$allow_id"; acl_host ip-deny.local "$deny_id"
sleep 2
PATH_=/
want "$(host_code basic.local)" 401 "Basic Auth without a login"
curl -sS --max-time 10 -H 'Host: basic.local' "$HTTP/" | grep -q 'Sign-in required' \
  || fail "Basic Auth: the 401 is not the page of NginxionS"
want "$(host_code basic.local -u alice:wonderland1)" 200 "Basic Auth with the password"
want "$(host_code ip-allow.local)" 200 "IP list, the allowed address"
want "$(host_code ip-deny.local)" 403 "IP list, a refused address"

# --- phase 3 ---

step "RBAC: built-in roles exist"
roles=$($CURL "$ADMIN/api/nginxions/rbac/roles" | tr -d ' \n')
analyst_role=$(echo "$roles" | grep -o '"id":[0-9]*,"name":"[^"]*","description":"[^"]*","builtin":"security_analyst"' \
  | grep -o '^"id":[0-9]*' | grep -o '[0-9]*')
[ -n "$analyst_role" ] || fail "no Security Analyst role: $roles"

step "RBAC: a Security Analyst"
analyst_id=$($CURL -H 'Content-Type: application/json' "$ADMIN/api/users" \
  -d '{"name": "Analyst", "nickname": "analyst", "email": "analyst@nginxions.test", "roles": [], "is_disabled": false}' \
  | tr -d ' \n' | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/users/$analyst_id/auth" \
  -d "{\"type\": \"password\", \"secret\": \"$PASSWORD-analyst\"}" > /dev/null
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/rbac/users/$analyst_id" \
  -d "{\"roles\": [$analyst_role]}" > /dev/null
AJAR=/tmp/analyst-cookies
curl -sS -k -c $AJAR -H 'Content-Type: application/json' "$ADMIN/api/tokens" \
  -d "{\"identity\": \"analyst@nginxions.test\", \"secret\": \"$PASSWORD-analyst\"}" > /dev/null
as_analyst() { curl -sS -k -b $AJAR -o /dev/null -w '%{http_code}' "$@"; }
expect() { [ "$1" = "$2" ] || fail "$3: expected $2, got $1"; }

step "RBAC: the analyst sees hosts, WAF and events"
expect "$(as_analyst "$ADMIN/api/nginx/proxy-hosts")" 200 "analyst lists proxy hosts"
expect "$(as_analyst "$ADMIN/api/nginxions/events")" 200 "analyst reads WAF events"
expect "$(as_analyst "$ADMIN/api/nginxions/waf/policy")" 200 "analyst reads the WAF policy"

step "RBAC: the analyst changes the WAF mode, not the host"
expect "$(as_analyst -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/hosts/1" \
  -d '{"enabled": true, "mode": "detect-learn", "minimum_confidence": "high"}')" 200 "analyst sets the WAF mode"
expect "$(as_analyst -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginx/proxy-hosts/1" \
  -d '{"forward_port": 81}')" 403 "analyst changes a proxy host"
expect "$(as_analyst -X DELETE "$ADMIN/api/nginx/proxy-hosts/1")" 403 "analyst deletes a proxy host"
expect "$(as_analyst -X POST "$ADMIN/api/nginxions/services/nginxions/restart")" 403 "analyst restarts a service"
expect "$(as_analyst "$ADMIN/api/users")" 403 "analyst lists users"
expect "$(as_analyst -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/rbac/users/$analyst_id" \
  -d '{"roles": [1]}')" 403 "analyst makes itself an administrator"

step "RBAC: the last administrator keeps the role"
code=$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' \
  "$ADMIN/api/nginxions/rbac/users/1" -d '{"roles": []}')
expect "$code" 400 "removing the last administrator"

step "RBAC: a role of chosen hosts sees test.local, not another host of the administrator"
other_id=$($CURL -H 'Content-Type: application/json' "$ADMIN/api/nginx/proxy-hosts" -d '{
  "domain_names": ["other.local"], "forward_scheme": "http", "forward_host": "test-upstream", "forward_port": "80"
}' | tr -d ' \n' | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')
scoped_role=$($CURL -H 'Content-Type: application/json' "$ADMIN/api/nginxions/rbac/roles" -d '{"name": "test.local team",
  "scope": "hosts", "hosts": [{"host_type": "proxy_host", "host_id": 1}], "permissions": ["proxy_hosts:view"]}' \
  | tr -d ' \n' | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/rbac/users/$analyst_id" \
  -d "{\"roles\": [$scoped_role]}" > /dev/null
seen=$(curl -sS -k -b $AJAR "$ADMIN/api/nginx/proxy-hosts" | tr -d ' \n')
echo "$seen" | grep -q '"domain_names":\["test.local"\]' || fail "the role does not see its host: $seen"
echo "$seen" | grep -q 'other.local' && fail "the role sees a host it was not given: $seen"
expect "$(as_analyst "$ADMIN/api/nginx/proxy-hosts/$other_id")" 404 "the role opens a host it was not given"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/rbac/users/$analyst_id" \
  -d "{\"roles\": [$analyst_role]}" > /dev/null
$CURL -X DELETE "$ADMIN/api/nginx/proxy-hosts/$other_id" > /dev/null

# --- phase 4 ---

step "events: stored events are filtered and exported"
$CURL "$ADMIN/api/nginxions/events?kind=all&limit=1" | grep -q '"total":' || fail "events are not listed"
$CURL "$ADMIN/api/nginxions/events/export?format=csv&kind=all" | head -1 | grep -q 'time,severity,action' \
  || fail "CSV export has no header"

step "events: the retention is set in the GUI (not by the analyst)"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/events/settings" \
  -d '{"days": 7, "aggregate_days": 90}' | grep -q '"days": *7' || fail "retention was not saved"
expect "$(as_analyst -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/events/settings" \
  -d '{"days": 1, "aggregate_days": 1}')" 403 "analyst changes the retention"

step "analytics: every request is in the request log (search, filters, export, pages, Events → All); a domain that is not a host is marked, CrowdSec counts as attacks"
curl -sS --max-time 10 -o /dev/null -H 'Host: not-a-host.local' "$HTTP/smoke-unknown" || true
curl -sS --max-time 10 -o /dev/null -H 'Host: test.local' "$HTTP/smoke-known" || true
for i in $(seq 1 20); do
  log=$($CURL "$ADMIN/api/nginxions/analytics/requests?unknown=1&path=/smoke-unknown&limit=5")
  echo "$log" | grep -q '"host": *"not-a-host.local"' && break
  [ "$i" = 20 ] && fail "the request to a domain that is not a host is not in the request log: $log"
  sleep 2
done
echo "$log" | grep -q '"known": *false' || fail "not-a-host.local is not marked as unknown: $log"
$CURL "$ADMIN/api/nginxions/analytics/requests?path=/smoke-known&limit=5" | grep -q '"known": *true' \
  || fail "the request to test.local is not in the request log as a known host"
# the log is read every 5 s and the ingest of the agent's log ran every 5 s too: it dropped the position of the
# request log, which was read again from its start (each request stored hundreds of times)
sleep 16
known=$($CURL "$ADMIN/api/nginxions/analytics/requests?path=/smoke-known&limit=1" | grep -o '"total": *[0-9]*' | grep -o '[0-9]*$')
[ "$known" = 1 ] || fail "one request is stored $known times in the request log"
$CURL "$ADMIN/api/nginxions/analytics/requests?q=smoke-unknown&status=4xx,5xx,2xx,3xx&maxMs=60000&limit=5" \
  | grep -q '"not-a-host.local"' || fail "Events → Requests: search and filters miss the request"
$CURL "$ADMIN/api/nginxions/analytics/requests/export?format=csv&q=smoke-unknown" | grep -q 'not-a-host.local' \
  || fail "Events → Requests: the export misses the request"
$CURL "$ADMIN/api/nginxions/events?kind=all&q=smoke-unknown&limit=5" | grep -q '"kind": *"request"' \
  || fail "Events → All: the requests of the log are missing"
$CURL "$ADMIN/api/nginxions/analytics/requests?q=smoke-unknown&limit=1" | grep -q '"total":' \
  || fail "Events → Requests: no count for the pages"
for tab in requests visitors performance security cache origin; do
  $CURL "$ADMIN/api/nginxions/analytics/traffic?tab=$tab&period=1h" | grep -q '"kpi":' || fail "analytics tab $tab"
done
$CURL "$ADMIN/api/nginxions/analytics/traffic?tab=requests&period=1h&unknown=1" | grep -q '"not-a-host.local"' \
  || fail "the top hosts of Analytics miss the unknown domain"

step "notifications: a webhook channel delivers a test message"
hook=$($CURL -X POST -H 'Content-Type: application/json' "$ADMIN/api/nginxions/notifications/channels" \
  -d '{"name": "smoke", "type": "webhook", "config": {"url": "http://test-upstream/nginxions-hook", "secret": "k"}}')
hook_id=$(echo "$hook" | grep -o '"id": *[0-9]*' | head -1 | grep -o '[0-9]*$')
[ -n "$hook_id" ] || fail "webhook channel was not created: $hook"
echo "$hook" | grep -q '"secret"' && fail "the webhook secret is returned by the API"
$CURL -X POST "$ADMIN/api/nginxions/notifications/channels/$hook_id/test" | grep -q '"ok": *true' \
  || fail "test message through the webhook was not delivered"

step "notifications: an unreachable mail server is an error, not a hang"
mail=$($CURL -X POST -H 'Content-Type: application/json' "$ADMIN/api/nginxions/notifications/channels" \
  -d '{"name": "smoke mail", "type": "email", "config": {"host": "127.0.0.1", "port": 2, "security": "none", "from": "nginxions@example.test", "to": ["admin@example.test"]}}')
mail_id=$(echo "$mail" | grep -o '"id": *[0-9]*' | head -1 | grep -o '[0-9]*$')
$CURL --max-time 30 -X POST "$ADMIN/api/nginxions/notifications/channels/$mail_id/test" | grep -q '"ok": *false' \
  || fail "a mail server that does not answer was not reported"

step "notifications: a rule is created; the analyst cannot add channels"
$CURL -X POST -H 'Content-Type: application/json' "$ADMIN/api/nginxions/notifications/rules" \
  -d "{\"name\": \"smoke\", \"type\": \"cert_expiry\", \"params\": {\"days\": 30}, \"channel_ids\": [$hook_id]}" \
  | grep -q '"type": *"cert_expiry"' || fail "rule was not created"
expect "$(as_analyst "$ADMIN/api/nginxions/notifications")" 200 "analyst reads notifications"
expect "$(as_analyst -X POST -H 'Content-Type: application/json' "$ADMIN/api/nginxions/notifications/channels" \
  -d '{"name": "x", "type": "webhook", "config": {"url": "http://x"}}')" 403 "analyst adds a channel"

step "system settings: an env setting is saved for the next start, a bad value is refused"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/system/settings" \
  -d '{"values": [{"env": "NGINX_LOG_NOT_FOUND", "value": true}]}' | grep -q '"restartRequired": *true' \
  || fail "a saved env setting is not pending"
$CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/system/settings" \
  -d '{"values": [{"env": "NGINX_LOG_NOT_FOUND", "value": false}]}' | grep -q '"restartRequired": *false' \
  || fail "the setting back to its running value is still pending"
code=$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' \
  "$ADMIN/api/nginxions/system/settings" -d '{"values": [{"env": "TZ", "value": "../../etc/passwd"}]}')
expect "$code" 400 "a bad time zone"
expect "$(as_analyst -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/system/settings" \
  -d '{"values": [{"env": "DISABLE_HTTP", "value": true}]}')" 403 "analyst changes system settings"

# --- phase 6 ---

# the first number "id" of a JSON answer
json_id() { tr -d ' \n' | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*$'; }
# a PEM field of a JSON answer as a file
json_pem() { tr -d '\n' | sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" | awk '{ gsub(/\\n/, "\n"); printf "%s", $0 }' > "$2"; }
api_json() { $CURL -H 'Content-Type: application/json' "$@"; }
HTTPS_MTLS="https://mtls.local"
TLS_TO="--connect-to mtls.local:443:nginxions:443"

step "PKI: a root CA and a trust domain"
root_id=$(api_json "$ADMIN/api/nginxions/pki/cas" \
  -d '{"kind": "root", "name": "Smoke Root", "subject": {"common_name": "Smoke Root", "organization": "NginxionS"}}' | json_id)
[ -n "$root_id" ] || fail "root CA was not created"
domain_id=$(api_json "$ADMIN/api/nginxions/pki/cas" -d "{\"kind\": \"intermediate\", \"name\": \"Smoke Office\",
  \"parent_id\": $root_id, \"subject\": {\"common_name\": \"Smoke Office\", \"organization\": \"NginxionS\"}}" | json_id)
[ -n "$domain_id" ] || fail "trust domain was not created"
other_id=$(api_json "$ADMIN/api/nginxions/pki/cas" -d "{\"kind\": \"intermediate\", \"name\": \"Smoke Partners\",
  \"parent_id\": $root_id, \"subject\": {\"common_name\": \"Smoke Partners\", \"organization\": \"NginxionS\"}}" | json_id)
expect "$(as_analyst -X POST -H 'Content-Type: application/json' "$ADMIN/api/nginxions/pki/cas" \
  -d '{"kind": "root", "name": "x", "subject": {"common_name": "x"}}')" 403 "analyst creates a CA"

step "PKI: a server certificate of the trust domain becomes a certificate of NPMplus"
server=$(api_json "$ADMIN/api/nginxions/pki/certs" -d "{\"ca_id\": $domain_id, \"profile\": \"server\",
  \"subject\": {\"common_name\": \"mtls.local\"}, \"sans\": {\"dns\": [\"mtls.local\"]}, \"install\": true}")
tls_id=$(echo "$server" | tr -d ' \n' | grep -o '"certificate_id":[0-9]*' | grep -o '[0-9]*$')
[ -n "$tls_id" ] || fail "server certificate was not installed: $server"
host_id=$(api_json "$ADMIN/api/nginx/proxy-hosts" -d "{\"domain_names\": [\"mtls.local\"], \"forward_scheme\": \"http\",
  \"forward_host\": \"test-upstream\", \"forward_port\": \"80\", \"certificate_id\": $tls_id}" | json_id)
[ -n "$host_id" ] || fail "proxy host mtls.local was not created"

step "mTLS: the host requires a certificate of the trust domain with OU=IT"
api_json -X PUT "$ADMIN/api/nginxions/mtls/proxy_host/$host_id" -d "{\"enabled\": true, \"ca_ids\": [$domain_id],
  \"rules\": [{\"field\": \"organizational_unit\", \"op\": \"one_of\", \"values\": [\"IT\"]}]}" \
  | tr -d ' \n' | grep -q '"nginx_online":true' || fail "nginx did not take the mTLS of the host"

# a client certificate as PEM files (the tester has no openssl to open a .p12)
client() { # name, OU, CA id → /tmp/<name>.crt, /tmp/<name>.key
  answer=$(api_json "$ADMIN/api/nginxions/pki/certs" -d "{\"ca_id\": $3, \"profile\": \"client\",
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
  $CURL "$ADMIN/api/nginxions/events?kind=mtls&limit=5" | grep -q '"name": *"mTLS: no client certificate"' && break
  [ "$i" = 15 ] && fail "no mTLS event: $($CURL "$ADMIN/api/nginxions/events?kind=mtls&limit=5")"
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
expect "$(curl -sS -k -o /dev/null -w '%{http_code}' "$ADMIN/api/nginxions/pki/public/crl/$domain_id.crl")" 200 "the CRL"

step "PKI: a revoked certificate is refused within a minute"
alice_id=$(echo "$alice" | tr -d ' \n' | grep -o '"certificate":{"id":[0-9]*' | grep -o '[0-9]*$')
api_json "$ADMIN/api/nginxions/pki/certs/revoke" -d "{\"ids\": [$alice_id], \"reason\": \"keyCompromise\"}" \
  | grep -q '"revoked": *1' || fail "alice was not revoked"
for i in $(seq 1 30); do
  [ "$(mtls --cert /tmp/alice.crt --key /tmp/alice.key)" = 403 ] && break
  [ "$i" = 30 ] && fail "the revoked certificate still opens the host after a minute"
  sleep 2
done

step "mTLS: revocation by OCSP refuses a revoked certificate within a minute and a half, nginx is not reloaded"
api_json -X PUT "$ADMIN/api/nginxions/mtls/proxy_host/$host_id" -d "{\"enabled\": true, \"ca_ids\": [$domain_id],
  \"rules\": [{\"field\": \"organizational_unit\", \"op\": \"one_of\", \"values\": [\"IT\"]}], \"revocation\": \"ocsp\"}" \
  | tr -d ' \n' | grep -q '"revocation":"ocsp"' || fail "the host did not take revocation by OCSP"
erin=$(client erin IT "$domain_id")
for i in $(seq 1 15); do
  [ "$(mtls --cert /tmp/erin.crt --key /tmp/erin.key)" = 200 ] && break
  [ "$i" = 15 ] && fail "OCSP: the host does not let erin in"
  sleep 2
done
erin_id=$(echo "$erin" | tr -d ' \n' | grep -o '"certificate":{"id":[0-9]*' | grep -o '[0-9]*$')
api_json "$ADMIN/api/nginxions/pki/certs/revoke" -d "{\"ids\": [$erin_id], \"reason\": \"keyCompromise\"}" \
  | grep -q '"revoked": *1' || fail "erin was not revoked"
for i in $(seq 1 45); do
  [ "$(mtls --cert /tmp/erin.crt --key /tmp/erin.key)" = 403 ] && break
  [ "$i" = 45 ] && fail "OCSP: the revoked certificate still opens the host"
  sleep 2
done

step "PKI: a service renews its short-lived certificate with its token, the token works once"
svc=$(api_json "$ADMIN/api/nginxions/pki/certs" -d "{\"ca_id\": $domain_id, \"profile\": \"client\",
  \"subject\": {\"common_name\": \"smoke-svc\"}, \"auto_renew\": \"token\", \"hours\": 2}" | tr -d ' \n')
svc_token=$(echo "$svc" | grep -o '"renew_token":"[^"]*"' | cut -d'"' -f4)
[ -n "$svc_token" ] || fail "no renewal token: $svc"
renewed=$(curl -sS -k --max-time 30 -X POST "$ADMIN/api/nginxions/pki/public/renew" -H "Authorization: Bearer $svc_token" \
  -H 'Content-Type: application/json' -d '{}' | tr -d ' \n')
echo "$renewed" | grep -q 'BEGINCERTIFICATE' || fail "the service was not renewed: $renewed"
echo "$renewed" | grep -q '"renew_token":"[^"]' || fail "no new token after the renewal: $renewed"
expect "$(curl -sS -k -o /dev/null -w '%{http_code}' -X POST "$ADMIN/api/nginxions/pki/public/renew" \
  -H "Authorization: Bearer $svc_token" -H 'Content-Type: application/json' -d '{}')" 401 "the used renewal token"

step "mTLS in one step: the switch of a host creates its trust domain, an access certificate opens it"
quick_id=$(api_json "$ADMIN/api/nginx/proxy-hosts" -d "{\"domain_names\": [\"quick.local\"], \"forward_scheme\": \"http\",
  \"forward_host\": \"test-upstream\", \"forward_port\": \"80\", \"certificate_id\": $tls_id}" | json_id)
[ -n "$quick_id" ] || fail "proxy host quick.local was not created"
quick=$(api_json -X POST "$ADMIN/api/nginxions/mtls/proxy_host/$quick_id/enable" | tr -d ' \n')
echo "$quick" | grep -q '"enabled":true' || fail "mTLS was not turned on: $quick"
quick_ca=$(echo "$quick" | grep -o '"ca_ids":\[[0-9]*' | grep -o '[0-9]*$')
$CURL "$ADMIN/api/nginxions/pki/cas/$quick_ca" | grep -q '"host": *"proxy_host-'"$quick_id"'"' \
  || fail "the trust domain of quick.local is not its own"
dana=$(client dana IT "$quick_ca")
quick_mtls() { curl -sS -k --max-time 10 --connect-to quick.local:443:nginxions:443 -o /dev/null -w '%{http_code}' "$@" https://quick.local/; }
for i in $(seq 1 15); do
  [ "$(quick_mtls --cert /tmp/dana.crt --key /tmp/dana.key)" = 200 ] && break
  [ "$i" = 15 ] && fail "the access certificate does not open quick.local"
  sleep 2
done
expect "$(quick_mtls)" 403 "quick.local without a certificate"
expect "$(quick_mtls --cert /tmp/carol.crt --key /tmp/carol.key)" 403 "quick.local with a certificate of another domain"
expect "$(mtls --cert /tmp/dana.crt --key /tmp/dana.key)" 403 "mtls.local with the access certificate of quick.local"
# dana is the only certificate of the trust domain of quick.local
$CURL "$ADMIN/api/nginxions/pki" | tr -d ' \n' | grep -q '{"host_type":"proxy_host","host_id":'"$quick_id"',"name":"quick.local"}' \
  || fail "the certificate does not list quick.local as what it opens"

step "mTLS: a deleted access certificate is revoked and gone from the list"
dana_id=$(echo "$dana" | tr -d ' \n' | grep -o '"certificate":{"id":[0-9]*' | grep -o '[0-9]*$')
api_json "$ADMIN/api/nginxions/pki/certs/delete" -d "{\"ids\": [$dana_id]}" | tr -d ' \n' \
  | grep -q '"deleted":1,"revoked":1' || fail "dana was not deleted"
for i in $(seq 1 30); do
  [ "$(quick_mtls --cert /tmp/dana.crt --key /tmp/dana.key)" = 403 ] && break
  [ "$i" = 30 ] && fail "the deleted certificate still opens quick.local"
  sleep 2
done
$CURL "$ADMIN/api/nginxions/pki" | grep -q '"common_name": *"dana"' && fail "the deleted certificate is still listed"

step "mTLS: a refused client gets the page the host chose (404, no answer), a valid certificate still passes"
denied() { # page → the mTLS of mtls.local with that page
  api_json -X PUT "$ADMIN/api/nginxions/mtls/proxy_host/$host_id" -d "{\"enabled\": true, \"ca_ids\": [$domain_id],
    \"rules\": [{\"field\": \"organizational_unit\", \"op\": \"one_of\", \"values\": [\"IT\"]}], \"revocation\": \"ocsp\",
    \"denied_page\": \"$1\"}" | tr -d ' \n' | grep -q "\"denied_page\":\"$1\"" || fail "mtls.local did not take the page $1"
}
# after a change old nginx workers still answer for a moment (graceful reload, reuseport): each check is repeated
eventually() { # description, command... → fails after 15 tries
  what=$1; shift
  for i in $(seq 1 15); do "$@" && return 0; [ "$i" = 15 ] && fail "$what"; sleep 1; done
}
mtls_code() { want=$1; shift; [ "$(mtls "$@" 2>/dev/null)" = "$want" ]; }
page_404() { curl -s -k --max-time 10 $TLS_TO "$HTTPS_MTLS/" | grep -q 'This site is not here'; }
denied not_found
eventually "no certificate: expected 404" mtls_code 404
eventually "the 404 page of NginxionS was not shown" page_404
eventually "a certificate refused by a rule: expected 404" mtls_code 404 --cert /tmp/bob.crt --key /tmp/bob.key
denied close
eventually "no certificate: expected no answer" mtls_code 000
eventually "a certificate of another host: expected no answer" mtls_code 000 --cert /tmp/dana.crt --key /tmp/dana.key
denied certificate
eventually "no certificate: expected 403 again" mtls_code 403

step "mTLS on a TCP stream: a certificate of the trust domain passes, none or a revoked one is refused"
stream_id=$(api_json "$ADMIN/api/nginx/streams" -d "{\"incoming_port\": 9555, \"forwarding_host\": \"test-upstream\",
  \"forwarding_port\": 80, \"tcp_forwarding\": true, \"udp_forwarding\": false, \"certificate_id\": $tls_id}" | json_id)
[ -n "$stream_id" ] || fail "the TLS stream :9555 was not created"
api_json -X PUT "$ADMIN/api/nginxions/mtls/stream/$stream_id" -d "{\"enabled\": true, \"ca_ids\": [$domain_id]}" \
  | tr -d ' \n' | grep -q '"enabled":true' || fail "the stream did not take mTLS"
expect "$(curl -sS -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' -b $JAR -k \
  "$ADMIN/api/nginxions/mtls/stream/$stream_id" -d "{\"enabled\": true, \"ca_ids\": [$domain_id], \"revocation\": \"ocsp\"}")" \
  400 "OCSP on a stream"
stream_tls() { curl -s -k --max-time 10 -o /dev/null -w '%{http_code}' "$@" https://nginxions:9555/; }
gwen=$(client gwen IT "$domain_id")
for i in $(seq 1 15); do
  [ "$(stream_tls --cert /tmp/gwen.crt --key /tmp/gwen.key)" = 200 ] && break
  [ "$i" = 15 ] && fail "the stream does not let gwen in"
  sleep 2
done
expect "$(stream_tls)" 000 "the stream without a certificate"
expect "$(stream_tls --cert /tmp/carol.crt --key /tmp/carol.key)" 000 "the stream with a certificate of another domain"
gwen_id=$(echo "$gwen" | tr -d ' \n' | grep -o '"certificate":{"id":[0-9]*' | grep -o '[0-9]*$')
api_json "$ADMIN/api/nginxions/pki/certs/revoke" -d "{\"ids\": [$gwen_id], \"reason\": \"keyCompromise\"}" \
  | grep -q '"revoked": *1' || fail "gwen was not revoked"
for i in $(seq 1 30); do
  [ "$(stream_tls --cert /tmp/gwen.crt --key /tmp/gwen.key)" = 000 ] && break
  [ "$i" = 30 ] && fail "the revoked certificate still opens the stream"
  sleep 2
done
$CURL -X DELETE "$ADMIN/api/nginx/streams/$stream_id" > /dev/null

step "PKI: a revoked trust domain takes its certificates with it and issues nothing more"
api_json "$ADMIN/api/nginxions/pki/cas/$other_id/revoke" -d '{"reason": "keyCompromise"}' | tr -d ' \n' \
  | grep -q '"revoke_reason":"keyCompromise"' || fail "the trust domain Smoke Partners was not revoked"
carol_reason=$($CURL "$ADMIN/api/nginxions/pki" | tr -d ' \n' | sed -n 's/.*"common_name":"carol",\(.*\)/\1/p' \
  | grep -o '"revoke_reason":[^,]*' | head -1)
expect "$carol_reason" '"revoke_reason":"CACompromise"' "the certificate of carol revoked with its CA"
expect "$(curl -sS -k -b $JAR -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  "$ADMIN/api/nginxions/pki/certs" -d "{\"ca_id\": $other_id, \"profile\": \"client\", \"subject\": {\"common_name\": \"x\"}}")" \
  400 "issuing with a revoked CA"

step "Certificates: the registry lists the TLS certificate and the CAs of the PKI, without the deleted one"
registry=$($CURL "$ADMIN/api/nginxions/certificates?limit=200" | tr -d ' \n')
echo "$registry" | grep -q '"source":"tls"' || fail "no TLS certificate in the registry: $registry"
echo "$registry" | grep -q '"name":"SmokeOffice"' || fail "no trust domain in the registry: $registry"
echo "$registry" | grep -q '"name":"dana"' && fail "the deleted certificate is in the registry"
$CURL "$ADMIN/api/nginxions/certificates?source=pki&status=revoked&q=alice" | grep -q '"name": *"alice"' \
  || fail "the revoked certificate is not found by its status"

step "Audit log: pages from the server and the action filter"
audit=$($CURL "$ADMIN/api/nginxions/audit?action=revoked&limit=1" | tr -d ' \n')
echo "$audit" | grep -q '"action":"revoked"' || fail "no revoked entry in the audit log: $audit"
echo "$audit" | grep -q '"total":[1-9]' || fail "the audit log has no total: $audit"

step "PKI: a root with a trust domain and a certificate is deleted together with them (cascade)"
cascade_root=$(api_json "$ADMIN/api/nginxions/pki/cas" \
  -d '{"kind": "root", "name": "Smoke Cascade", "subject": {"common_name": "Smoke Cascade"}}' | json_id)
cascade_domain=$(api_json "$ADMIN/api/nginxions/pki/cas" -d "{\"kind\": \"intermediate\", \"name\": \"Smoke Cascade Domain\",
  \"parent_id\": $cascade_root, \"subject\": {\"common_name\": \"Smoke Cascade Domain\"}}" | json_id)
[ -n "$cascade_domain" ] || fail "the cascade trust domain was not created"
api_json "$ADMIN/api/nginxions/pki/certs" -d "{\"ca_id\": $cascade_domain, \"profile\": \"client\",
  \"subject\": {\"common_name\": \"cascade\"}}" > /dev/null
expect "$(curl -sS -k -b "$JAR" -o /dev/null -w '%{http_code}' -X DELETE "$ADMIN/api/nginxions/pki/cas/$cascade_root")" 400 \
  "a root with a trust domain deleted without cascade"
$CURL -X DELETE "$ADMIN/api/nginxions/pki/cas/$cascade_root?cascade=true" | grep -q true || fail "cascade delete failed"
if $CURL "$ADMIN/api/nginxions/pki" | grep -q 'Smoke Cascade'; then fail "the cascade left a CA behind"; fi

step "PKI: deleting the trust domain of a host turns its mTLS off and leaves no copy of the CA behind"
$CURL -X DELETE "$ADMIN/api/nginxions/pki/cas/$quick_ca?cascade=true&disable_hosts=true" | grep -q true \
  || fail "the trust domain of quick.local was not deleted"
$CURL "$ADMIN/api/nginxions/mtls/proxy_host/$quick_id" | tr -d ' \n' | grep -q '"enabled":false' \
  || fail "mTLS of quick.local is still on"
if $CURL "$ADMIN/api/nginxions/certificates?limit=200" | grep -q "proxy_host-$quick_id\.ca\.pem"; then
  fail "the CA file of quick.local is left in the registry"
fi

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
  $CURL --max-time 300 -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/crowdsec/settings" -d "{
  \"bouncer\": {\"enabled\": true, \"admin\": false, \"mode\": \"live\", \"fallback\": \"ban\", \"update_frequency\": 10,
    \"exclude_locations\": [], \"captcha\": {\"provider\": \"\", \"site_key\": \"\", \"secret_key\": \"\"}},
  \"sources\": {\"nginx\": true, \"openappsec\": true},
  \"appsec\": {\"enabled\": $1, \"failure_action\": \"passthrough\", \"configs\": [\"crowdsecurity/appsec-default\"]},
  \"profiles\": [{\"name\": \"ip\", \"enabled\": true, \"scope\": \"Ip\", \"scenarios\": [], \"filter\": \"$2\",
    \"type\": \"ban\", \"duration\": \"4h\", \"escalate\": false}],
  \"allowlist\": {\"ips\": [], \"expressions\": [], \"private\": false},
  \"openappsec_ban\": {\"enabled\": true, \"events\": 3, \"minutes\": 10}, \"log_level\": \"info\", \"online_hub\": false}"
}

step "CrowdSec: the local API answers, NginxionS is a machine of its own"
for i in $(seq 1 30); do
  $CURL "$ADMIN/api/nginxions/crowdsec" | tr -d ' \n' | grep -q '"lapi":{"healthy":true' && break
  [ "$i" = 30 ] && fail "the local API of CrowdSec does not answer: $($CURL "$ADMIN/api/nginxions/crowdsec")"
  sleep 2
done
$CURL "$ADMIN/api/nginxions/crowdsec/registry" | grep -q '"name": *"nginxions-' || fail "NginxionS is not a machine of CrowdSec"

# the closed network has private addresses only: they are not allowlisted here
step "CrowdSec: settings from the GUI are applied (bouncer and AppSec on)"
cs_settings true "" | tr -d ' \n' | grep -q '"\(restarted\|reloaded\)":true' || fail "the settings were not applied"

# profiles, acquisition, allowlists and scenarios are reread on SIGHUP: no restart of the container
step "CrowdSec: a change of a profile is applied by a reload, not a restart"
cs_started() { $CURL "$ADMIN/api/nginxions/services/crowdsec" | grep -o '"startedAt": *"[^"]*"'; }
before=$(cs_started)
cs_settings true "Alert.GetScope() == 'Ip'" | tr -d ' \n' | grep -q '"reloaded":true' \
  || fail "the profile change was not applied by a reload"
[ "$(cs_started)" = "$before" ] || fail "CrowdSec was restarted for a profile change"

step "CrowdSec: a broken profile is refused at the start of CrowdSec, the previous files come back"
answer=$(cs_settings true "Alert.Broken(((" 2>&1 || true)
echo "$answer" | grep -q 'previous ones are restored' || fail "a broken profile was not rolled back: $answer"
$CURL "$ADMIN/api/nginxions/crowdsec" | tr -d ' \n' | grep -q '"lapi":{"healthy":true' \
  || fail "CrowdSec is not healthy after the rollback"
# the filter of the previous step comes back, not the broken one
$CURL "$ADMIN/api/nginxions/crowdsec/settings" | grep -q 'Alert.Broken' && fail "the broken profile was kept"
$CURL "$ADMIN/api/nginxions/crowdsec/settings" | grep -q "Alert.GetScope() == 'Ip'" || fail "the previous profile did not come back"

step "CrowdSec: a ban by hand blocks the tester on its hosts, not in the interface of NginxionS"
api_json "$ADMIN/api/nginxions/crowdsec/decisions" -d "{\"values\": [\"$client_ip\"], \"duration\": \"10m\", \"reason\": \"smoke\"}" \
  | grep -q '"count": *1' || fail "the ban was not added"
wait_page / 403 "test.local for a banned address"
$CURL "$ADMIN/api/nginxions/crowdsec/decisions?q=$client_ip" | grep -q '"scenario": *"nginxions/manual"' \
  || fail "the ban is not among the decisions"

step "CrowdSec: a host left out by the bouncer lets the banned address in"
api_json -X PUT "$ADMIN/api/nginxions/crowdsec/hosts/proxy_host/1" -d '{"bouncer": false}' > /dev/null
wait_page / 200 "test.local left out by the bouncer"
api_json -X PUT "$ADMIN/api/nginxions/crowdsec/hosts/proxy_host/1" -d '{"bouncer": true}' > /dev/null
wait_page / 403 "test.local checked by the bouncer again"

step "CrowdSec: unban lets the tester in"
api_json "$ADMIN/api/nginxions/crowdsec/decisions/delete" -d "{\"values\": [\"$client_ip\"]}" | grep -q '"deleted": *[1-9]' \
  || fail "the ban was not removed"
wait_page / 200 "test.local after the unban"

step "CrowdSec: AppSec blocks a probe of /.env, its alert becomes a security event"
wait_page /.env 403 "a probe of /.env with AppSec"
# the probe is sent again while waiting: AppSec of CrowdSec starts again with the settings above, and until it
# answers the bouncer lets the probe on to open-appsec, whose 403 makes no CrowdSec alert
for i in $(seq 1 45); do
  page /.env > /dev/null
  $CURL "$ADMIN/api/nginxions/events?kind=crowdsec&limit=5" | grep -q '"kind": *"crowdsec"' && break
  [ "$i" = 45 ] && fail "no CrowdSec alert in the events: $($CURL "$ADMIN/api/nginxions/events?kind=crowdsec&limit=5")"
  sleep 2
done
# the agents are one list, each row names its agent
$CURL "$ADMIN/api/nginxions/events?agent=crowdsec&limit=5" | grep -q '"kind": *"crowdsec"' \
  || fail "the CrowdSec alert is not in the events of the agents"
api_json "$ADMIN/api/nginxions/crowdsec/decisions/delete" -d "{\"values\": [\"$client_ip\"]}" > /dev/null || true

if $CURL "$ADMIN/api/nginxions/waf" | grep -q '"reachable": *true'; then
  step "CrowdSec: three requests blocked by open-appsec ban the address"
  # the WAF steps above leave test.local in detect-learn: the scenario counts blocked requests only
  $CURL -X PUT -H 'Content-Type: application/json' "$ADMIN/api/nginxions/waf/hosts/1" \
    -d '{"enabled": true, "mode": "prevent-learn", "minimum_confidence": "high"}' > /dev/null
  wait_status "$SQLI" 403 "SQLi is not blocked in prevent-learn again"
  for i in $(seq 1 30); do
    page "$SQLI" > /dev/null
    $CURL "$ADMIN/api/nginxions/crowdsec/decisions?q=$client_ip" | grep -q 'nginxions/openappsec-prevent' && break
    [ "$i" = 30 ] && fail "blocked requests of open-appsec did not ban: $($CURL "$ADMIN/api/nginxions/crowdsec/alerts?limit=5")"
    sleep 2
  done
  wait_page / 403 "test.local for an address banned for its attacks"
  api_json "$ADMIN/api/nginxions/crowdsec/decisions/delete" -d "{\"values\": [\"$client_ip\"]}" > /dev/null
  wait_page / 200 "test.local after the unban"
fi

step "CrowdSec: a blocklist file becomes decisions, the allowlist and bad lines are left out"
printf '# smoke\n203.0.113.10\n203.0.113.0/28 range\nnot-an-ip\n2001:db8::10\n' > /tmp/list.txt
list=$($CURL -X POST -H 'Content-Type: text/plain' --data-binary @/tmp/list.txt \
  "$ADMIN/api/nginxions/crowdsec/blocklists?name=smoke&duration=1h")
echo "$list" | tr -d ' \n' | grep -q '"count":3' || fail "the blocklist did not make 3 decisions: $list"
$CURL "$ADMIN/api/nginxions/crowdsec/decisions?origin=lists" | grep -q '"value": *"203.0.113.0/28"' \
  || fail "the range of the blocklist is not banned"

step "CrowdSec: other nodes take the decisions of this one with its token only"
api_json "$ADMIN/api/nginxions/crowdsec/decisions" -d '{"values": ["192.0.2.77"], "duration": "1h"}' > /dev/null
token=$(api_json -X PUT "$ADMIN/api/nginxions/crowdsec/share" -d '{"enabled": true}' | tr -d ' \n' \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
[ -n "$token" ] || fail "no token for other nodes"
expect "$(curl -sS -k -o /dev/null -w '%{http_code}' "$ADMIN/api/nginxions/crowdsec/public/decisions")" 403 "the export without a token"
export=$(curl -sS -k -H "Authorization: Bearer $token" "$ADMIN/api/nginxions/crowdsec/public/decisions")
echo "$export" | grep -q '^192.0.2.77$' || fail "the export has no decision by hand: $export"
echo "$export" | grep -q '203.0.113.10' && fail "the export has the decisions of a blocklist"
node=$(api_json "$ADMIN/api/nginxions/crowdsec/blocklists" -d "{\"name\": \"node\", \"source\": \"url\",
  \"url\": \"$ADMIN/api/nginxions/crowdsec/public/decisions\", \"token\": \"$token\", \"insecure\": true, \"refresh_minutes\": 60}")
echo "$node" | tr -d ' \n' | grep -q '"error":""' || fail "the decisions of another node were not taken: $node"

step "CrowdSec: a hub item installs from the offline snapshot and is removed again"
api_json --max-time 300 "$ADMIN/api/nginxions/crowdsec/hub" \
  -d '{"type": "collections", "name": "crowdsecurity/nextcloud", "action": "install"}' \
  | grep -q 'scenarios/crowdsecurity/nextcloud-bf' || fail "the collection did not install with its scenario"
$CURL "$ADMIN/api/nginxions/crowdsec/hub?type=collections&q=nextcloud&installed=true" | grep -q '"status": *"up-to-date"' \
  || fail "the installed collection is not up to date"
api_json --max-time 300 "$ADMIN/api/nginxions/crowdsec/hub" \
  -d '{"type": "collections", "name": "crowdsecurity/nextcloud", "action": "remove"}' \
  | grep -q 'collections/crowdsecurity/nextcloud' || fail "the collection was not removed"

step "CrowdSec: the machines and bouncers of the stack cannot be deleted, an unknown one is not found"
for target in machines/localhost bouncers/nginxions bouncers/appsec; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' -b "$JAR" -X DELETE "$ADMIN/api/nginxions/crowdsec/registry/$target")
  [ "$code" = 400 ] || fail "$target of the stack was not protected: HTTP $code"
done
code=$(curl -sk -o /dev/null -w '%{http_code}' -b "$JAR" -X DELETE "$ADMIN/api/nginxions/crowdsec/registry/machines/nope")
[ "$code" = 404 ] || fail "deleting an unknown machine: HTTP $code"

step "GeoIP: the database of CrowdSec gives countries offline, a file that is no database is refused"
$CURL "$ADMIN/api/nginxions/system/geoip" | grep -q '"type": *"GeoLite2' || fail "no GeoIP database: $($CURL "$ADMIN/api/nginxions/system/geoip")"
code=$(curl -sk -o /dev/null -w '%{http_code}' -b "$JAR" -X POST -H 'Content-Type: application/octet-stream' \
  --data-binary 'not a database' "$ADMIN/api/nginxions/system/geoip")
[ "$code" = 400 ] || fail "a broken GeoIP database was accepted: HTTP $code"

step "Hosts → Countries: nginx knows the countries; a host let in only for one country keeps answering private networks"
$CURL "$ADMIN/api/nginxions/geo" | grep -q '"available": *true' || fail "nginx has no GeoIP database: $($CURL "$ADMIN/api/nginxions/geo")"
geo_host=$($CURL -H 'Content-Type: application/json' "$ADMIN/api/nginx/dead-hosts" -d '{
  "domain_names": ["geo.local"], "meta": {"nginxions_geo": {"mode": "allow", "countries": ["AQ"], "action": "403"}}
}')
geo_id=$(echo "$geo_host" | grep -o '"id": *[0-9]*' | head -1 | grep -o '[0-9]*')
[ -n "$geo_id" ] || fail "the 404 host was not created: $geo_host"
# the answer of the creation comes before nginx has the config: its state is read back
for i in $(seq 1 15); do
  geo_host=$($CURL "$ADMIN/api/nginx/dead-hosts/$geo_id")
  echo "$geo_host" | grep -q '"nginx_online": *true' && break
  echo "$geo_host" | grep -q '"nginx_online": *false' && fail "nginx refused the countries of a host: $geo_host"
  [ "$i" = 15 ] && fail "nginx did not apply the 404 host: $geo_host"
  sleep 1
done
for i in $(seq 1 10); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: geo.local' "$HTTP/")
  [ "$code" = 404 ] && break
  [ "$i" = 10 ] && fail "a client of a private network was refused by the countries of the host: HTTP $code"
  sleep 1
done
$CURL -X DELETE "$ADMIN/api/nginx/dead-hosts/$geo_id" > /dev/null

step "Migration: a backup of NPM is read and analyzed; the import waits for a new NginxionS"
mig=$(curl -sS --max-time 120 -k -b $JAR -X POST -H 'Content-Type: application/octet-stream' \
  --data-binary @/fixtures/npm-backup.tgz "$ADMIN/api/nginxions/system/migration/upload")
echo "$mig" | grep -q '"kind": *"open-appsec-npm"' || fail "the backup was not recognised: $mig"
echo "$mig" | grep -q '"code": *"plain_passwords"' || fail "plain access list passwords not found: $mig"
echo "$mig" | grep -q '"table": *"proxy_host"' || fail "the import is not blocked by existing hosts: $mig"
code=$(curl -sk -o /dev/null -w '%{http_code}' -b "$JAR" -X POST -H 'Content-Type: application/json' -d '{}' \
  "$ADMIN/api/nginxions/system/migration/apply")
[ "$code" = 400 ] || fail "the import into an NginxionS with hosts was not refused: HTTP $code"
$CURL -X DELETE "$ADMIN/api/nginxions/system/migration" | grep -q '"stage": *"idle"' || fail "the migration was not discarded"

echo "OK: closed-network smoke passed"
