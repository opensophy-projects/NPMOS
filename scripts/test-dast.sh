#!/usr/bin/env bash
# DAST: brings up the production stack, sets it up like an administrator (deploy/test/dast-setup.sh) and attacks it
# from containers of its edge network, each with an address of its own (a ban of one scanner does not stop another):
#   OWASP ZAP   the API of the interface by its OpenAPI schema with a session (active scan), the pages of the
#               interface and the proxy host dast.local (passive: headers, cookies, leaks)
#   Nuclei      known CVEs, exposed panels and files, misconfigurations (the interface and the default host)
#   testssl.sh  TLS of the interface (port 81) and of the proxy host (443): protocols, ciphers, HSTS, known attacks
#   gixy        the nginx configuration the stack runs (nginx -T): SSRF, header injection, alias traversal...
#
#   NGINXIONS_REGISTRY=docker.io/opensophy NGINXIONS_VERSION=<tag> scripts/test-dast.sh
#
# Reports in $OUT (reports/dast). Exits non-zero only when the stack or a scanner fails: what fails the run is decided
# by scripts/security-report.mjs.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=../.github/security/tools.env
. .github/security/tools.env

OUT="${OUT:-reports/dast}"
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
  [ "${KEEP:-}" = 1 ] || "${compose[@]}" down -v --remove-orphans > /dev/null 2>&1 || true
  exit $status
}
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
scan zap-api zap -e ZAP_AUTH_HEADER=Cookie -e "ZAP_AUTH_HEADER_VALUE=__Host-Http-token=$cookie" \
  -e ZAP_AUTH_HEADER_SITE=nginxions "$ZAP_IMAGE" zap-api-scan.py -t https://nginxions:81/api/schema -f openapi \
  -J zap-api.json -r zap-api.html -I -z "-config scanner.maxScanDurationInMins=20 -config scanner.threadPerHost=4"
scan zap-ui zap "$ZAP_IMAGE" zap-baseline.py -t https://nginxions:81/ -J zap-ui.json -r zap-ui.html -I -m 3
scan zap-host zap "$ZAP_IMAGE" zap-baseline.py -t https://dast.local/ -J zap-host.json -r zap-host.html -I -m 3

# what NginxionS serves itself: the interface and the default host (80, 443). Not dast.local: its site (whoami) echoes
# every request back, which templates take for the product they look for.
scan nuclei "${run[@]}" "$NUCLEI_IMAGE" -silent -no-color -severity low,medium,high,critical \
  -rate-limit 60 -timeout 10 -u https://nginxions:81 -u http://nginxions -u https://nginxions -jsonl -o /out/nuclei.jsonl

# testssl.sh: its exit code counts findings; a report is what tells a finished scan
testssl() {
  local name=$1
  shift
  "${run[@]}" "$TESTSSL_IMAGE" --quiet --warnings off --color 0 --severity LOW --jsonfile "/out/$name.json" "$@" || true
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
echo "OK: DAST finished, reports in $OUT"
