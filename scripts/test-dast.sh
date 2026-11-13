#!/usr/bin/env bash
# DAST: brings up the production stack, sets it up like an administrator (deploy/test/dast-setup.sh) and attacks it
# from containers of its edge network, each with an address of its own (a ban of one scanner does not stop another):
#   OWASP ZAP   the API of the interface by its OpenAPI schema with a session (active scan), the pages of the
#               interface and the proxy host dast.local (passive: headers, cookies, leaks)
#   Nuclei      known CVEs, exposed panels and files, misconfigurations (the interface and the default host)
#   testssl.sh  TLS of the interface (port 81) and of the proxy host (443): protocols, ciphers, HSTS, known attacks
#   gixy        the nginx configuration the stack runs (nginx -T): SSRF, header injection, alias traversal...
# DAST_LEVEL=extended (the extended run of CI, docs/DEVSECOPS.md) goes further:
#   ZAP           full active scan of the pages and of dast.local, the API scan without its 20 minutes limit
#   Nuclei        info templates too, and the ones the templates ignore by default (intrusive), not dos
#   Schemathesis  fuzzing of the API by its OpenAPI schema with a session: server errors (500), operations that
#                 answer without authentication; after the other scanners, it changes data
#   runtime       scripts/check-runtime.sh: privileges, capabilities, namespaces, sockets of the running containers
#
#   NGINXIONS_REGISTRY=docker.io/opensophy NGINXIONS_VERSION=<tag> [DAST_LEVEL=extended] scripts/test-dast.sh
#
# Reports in $OUT (reports/dast). Exits non-zero only when the stack or a scanner fails: what fails the run is decided
# by scripts/security-report.mjs.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=../.github/security/tools.env
. .github/security/tools.env

OUT="${OUT:-reports/dast}"
DAST_LEVEL="${DAST_LEVEL:-full}"
mkdir -p "$OUT"
out="$(cd "$OUT" && pwd)"
# ZAP and testssl.sh run as users of their own
chmod 777 "$out"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-nginxions-dast}"
compose=(docker compose -f deploy/compose.yaml -f deploy/test/compose.dast.yaml)
net="${COMPOSE_PROJECT_NAME}_edge"

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    echo "--- logs (failure) ---"
    "${compose[@]}" logs --no-color --tail 60 || true
  fi
  # the log of the interface next to the reports: the cause of an error answer the scanners met (500 of ZAP)
  "${compose[@]}" logs --no-color nginxions 2> /dev/null | grep -v "ngx_cp\|ngx_http_cp" > "$out/nginxions.log" || true
  [ "${KEEP:-}" = 1 ] || "${compose[@]}" down -v --remove-orphans > /dev/null 2>&1 || true
  rm -rf "$templates"
  exit $status
}
templates=$(mktemp -d)
trap cleanup EXIT

"${compose[@]}" up -d --no-build nginxions openappsec crowdsec test-upstream

echo "==> waiting for nginxions to become healthy"
for i in $(seq 1 90); do
  state=$(docker inspect -f '{{.State.Health.Status}}' "$("${compose[@]}" ps -q nginxions)" 2> /dev/null || true)
  [ "$state" = healthy ] && break
  [ "$i" = 90 ] && { echo "nginxions is not healthy: $state"; exit 1; }
  sleep 2
done

echo "==> set up: admin, PKI certificate, proxy host dast.local"
"${compose[@]}" run --rm -T dast-setup
cookie=$("${compose[@]}" run --rm -T --entrypoint cat dast-setup /state/cookie)
[ -n "$cookie" ] || { echo "no session for the scanners"; exit 1; }
# the root CA of the PKI of the test: the interface and dast.local have certificates it issued
"${compose[@]}" run --rm -T --entrypoint cat dast-setup /state/ca.pem > "$out/dast-ca.pem"
ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$("${compose[@]}" ps -q openappsec)")
run=(docker run --rm --network "$net" --add-host "dast.local:$ip" -v "$out:/out")

echo "==> nginx configuration (gixy)"
"${compose[@]}" exec -T nginxions nginx -T > "$out/nginx-T.conf" 2> /dev/null
# exit 1: issues found (the report decides)
pipx run --spec "gixy-ng==$GIXY_VERSION" gixy -f json -o "$out/gixy.json" "$out/nginx-T.conf" || [ -s "$out/gixy.json" ]

# the scanners run side by side; each writes its own report, its log goes to $OUT/<name>.log
pids=()
scan() {
  local name=$1
  shift
  echo "==> $name"
  "$@" > "$out/$name.log" 2>&1 &
  pids+=("$!:$name")
}

# ZAP: exit 1/2 = alerts found (the report decides), 3 = the scan failed
zap() {
  local rc=0
  "${run[@]}" -v "$out:/zap/wrk:rw" "$@" || rc=$?
  [ "$rc" -le 2 ]
}
if [ "$DAST_LEVEL" = extended ]; then
  zap_api_minutes=60
  zap_pages=(zap-full-scan.py -m 5 -z "-config scanner.maxScanDurationInMins=30 -config scanner.threadPerHost=4")
else
  zap_api_minutes=20
  zap_pages=(zap-baseline.py -m 3)
fi
# the port of the proxy of ZAP is fixed (each scan has a container of its own): the random free port its scripts take
# is in the range of the outgoing ports, and an add-on download at its start took it ("Address already in use", the
# scan never started)
zap_pages+=(-P 8090)
scan zap-api zap -e ZAP_AUTH_HEADER=Cookie -e "ZAP_AUTH_HEADER_VALUE=__Host-Http-token=$cookie" \
  -e ZAP_AUTH_HEADER_SITE=nginxions "$ZAP_IMAGE" zap-api-scan.py -P 8090 -t https://nginxions:81/api/schema -f openapi \
  -J zap-api.json -r zap-api.html -I -z "-config scanner.maxScanDurationInMins=$zap_api_minutes -config scanner.threadPerHost=4"
scan zap-ui zap "$ZAP_IMAGE" "${zap_pages[@]}" -t https://nginxions:81/ -J zap-ui.json -r zap-ui.html -I
scan zap-host zap "$ZAP_IMAGE" "${zap_pages[@]}" -t https://dast.local/ -J zap-host.json -r zap-host.html -I

# what NginxionS serves itself: the interface and the default host (80, 443). Not dast.local: its site (whoami) echoes
# every request back, which templates take for the product they look for.
# Its templates are a pinned commit fetched with git (tools.env), not downloaded by Nuclei at its start (-duc).
echo "==> nuclei templates"
git -C "$templates" init -q
git -C "$templates" fetch -q --depth 1 https://github.com/projectdiscovery/nuclei-templates "$NUCLEI_TEMPLATES_REF"
git -C "$templates" checkout -q FETCH_HEAD
# The extended run: info templates too and no .nuclei-ignore of the templates (intrusive ones), except dos.
if [ "$DAST_LEVEL" = extended ]; then
  nuclei_mount=()
  nuclei_opts=(-severity "info,low,medium,high,critical" -etags dos)
else
  nuclei_mount=(-v "$templates/.nuclei-ignore:/root/.config/nuclei/.nuclei-ignore:ro")
  nuclei_opts=(-severity "low,medium,high,critical")
fi
scan nuclei "${run[@]}" -v "$templates:/templates:ro" "${nuclei_mount[@]}" \
  "$NUCLEI_IMAGE" -ud /templates -duc -silent -no-color "${nuclei_opts[@]}" \
  -rate-limit 60 -timeout 10 -u https://nginxions:81 -u http://nginxions -u https://nginxions -jsonl -o /out/nuclei.jsonl

# testssl.sh: its exit code counts findings; a report is what tells a finished scan
testssl() {
  local name=$1
  shift
  "${run[@]}" "$TESTSSL_IMAGE" --quiet --warnings off --color 0 --severity LOW --add-ca /out/dast-ca.pem \
    --jsonfile "/out/$name.json" "$@" || true
  [ -s "$out/$name.json" ]
}
scan testssl-ui testssl testssl-ui nginxions:81
scan testssl-host testssl testssl-host --ip one dast.local:443

failed=0
for p in "${pids[@]}"; do
  if ! wait "${p%%:*}"; then
    echo "FAIL: ${p#*:} did not finish (log: $OUT/${p#*:}.log)"
    tail -n 20 "$out/${p#*:}.log"
    failed=1
  fi
done
[ "$failed" = 0 ] || exit 1
# an empty report of Nuclei: nothing found
[ -e "$out/nuclei.jsonl" ] || touch "$out/nuclei.jsonl"

if [ "$DAST_LEVEL" = extended ]; then
  echo "==> runtime of the containers"
  scripts/check-runtime.sh "$COMPOSE_PROJECT_NAME" "$out/runtime.json"

  # last: its fuzzing creates, changes and deletes objects. The session stays: tokens and the accounts' own
  # authentication are left out. Exit 1 = failures found (the report decides); a run without its report failed.
  echo "==> schemathesis (fuzzing of the API, $SCHEMATHESIS_IMAGE)"
  "${run[@]}" "$SCHEMATHESIS_IMAGE" run https://nginxions:81/api/schema --url https://nginxions:81/api \
    --tls-verify false -H "Cookie: __Host-Http-token=$cookie" \
    --checks not_a_server_error,ignored_auth --max-time 900 --workers 4 --request-timeout 30 \
    --exclude-path-regex '^/(tokens|users/\{userID\})' --no-color \
    --report json --report-json-path /out/schemathesis.json > "$out/schemathesis.log" 2>&1 || true
  [ -s "$out/schemathesis.json" ] || { echo "FAIL: schemathesis left no report"; tail -n 30 "$out/schemathesis.log"; exit 1; }
fi
echo "OK: DAST finished, reports in $OUT"
