#!/usr/bin/env bash
# Trains the WAF model of NginxionS on the real agent and decides whether it may be released (docs/MODEL.md):
#   1. brings up the production stack with the feature dump of the agent (deploy/test/compose.training.yaml) and sets
#      it up like an administrator: a site train.local, the default policy in prevent mode, sources identified by
#      X-Forwarded-For (model/replay.py gives every request its own source);
#   2. sends every request of $SAMPLES through it with the stock model: the agent writes what it found in each value,
#      model/replay.py what it decided;
#   3. trains the new model on the training part (model/train.py);
#   4. installs it the way an administrator does (WAF -> Agent -> model upload; the agent restarts) and sends the
#      held-out part through it;
#   5. compares (model/evaluate.py): exit 1 when the new model may not be released.
#
#   NGINXIONS_REGISTRY=docker.io/opensophy NGINXIONS_VERSION=<tag> SAMPLES=samples.jsonl scripts/train-model.sh
#
# Results in $WORK (model-work): out/ (open-appsec-advanced-model.tgz, waap.data, model-card.json), metrics.json,
# report.md, the verdicts and the policy. PYTHON: a Python with model/requirements.txt.
set -euo pipefail

cd "$(dirname "$0")/.."
WORK="${WORK:-model-work}"
SAMPLES="${SAMPLES:?SAMPLES=<samples.jsonl of model/datasets.py>}"
PYTHON="${PYTHON:-python3}"
WORKERS="${WORKERS:-16}"
MODEL_NAME="${MODEL_NAME:-$(date -u +%F)}"
mkdir -p "$WORK"
work="$(cd "$WORK" && pwd)"
samples="$(cd "$(dirname "$SAMPLES")" && pwd)/$(basename "$SAMPLES")"
export NGINXIONS_FEATURES_DIR="$work/features"
rm -rf "$NGINXIONS_FEATURES_DIR" "$work/dump-stock" "$work/dump-new"
mkdir -p "$NGINXIONS_FEATURES_DIR" "$work/dump-stock"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-nginxions-train}"
compose=(docker compose -f deploy/compose.yaml -f deploy/test/compose.training.yaml)
ADMIN="https://127.0.0.1:${NGINXIONS_ADMIN_PORT:-81}"
SITE="http://127.0.0.1:${NGINXIONS_HTTP_PORT:-80}"
JAR="$work/cookies"
rm -f "$JAR"

step() { echo "==> $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
api() {
  local out code
  out=$(curl -sS --max-time 60 -k -b "$JAR" -c "$JAR" -w '\n%{http_code}' -H 'Content-Type: application/json' "$@")
  code=$(printf '%s' "$out" | tail -n 1)
  case "$code" in
    2*) printf '%s' "$out" | sed '$d' ;;
    *) fail "$* -> $code: $(printf '%s' "$out" | sed '$d')" ;;
  esac
}
# the verdict of the site for a request from a source of its own: 200 passed, 403 blocked
probe() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: train.local' -H "X-Forwarded-For: 10.9.9.$1" \
  -H 'X-Nginxions-Sample: probe' "$SITE$2" || true; }
XSS='/?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E'
# a round of 64 attacks over 16 connections at once (every nginx worker gets some): how many were not blocked
missed() {
  seq 1 64 | xargs -P 16 -I{} curl -s -o /dev/null -w '%{http_code}\n' --max-time 10 -H 'Host: train.local' \
    -H 'X-Forwarded-For: 10.9.8.{}' -H 'X-Nginxions-Sample: probe' "$SITE$XSS" | grep -vc '^403$' || true
}
# the WAF decides, and in every nginx worker: after a start of the agent the workers attach one by one, and one
# that has not yet lets requests through uninspected (fail-open)
wait_verdicts() {
  for i in $(seq 1 90); do
    ok=$(probe 1 '/?q=hello')
    blocked=$(probe 2 "$XSS")
    [ "$ok" = 200 ] && [ "$blocked" = 403 ] && break
    [ "$i" = 90 ] && fail "the WAF does not decide: a normal request -> $ok, XSS -> $blocked"
    sleep 2
  done
  clean=0
  for i in $(seq 1 60); do
    m=$(missed)
    if [ "$m" = 0 ]; then clean=$((clean + 1)); else clean=0; fi
    [ "$clean" = 3 ] && return 0
    [ "$i" = 60 ] && fail "the WAF lets attacks through: $m of 64 in the last round"
    sleep 5
  done
}

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    echo "--- logs (failure) ---"
    "${compose[@]}" logs --no-color --tail 80 openappsec nginxions || true
  fi
  [ "${KEEP:-}" = 1 ] || "${compose[@]}" down -v --remove-orphans > /dev/null 2>&1 || true
  exit $status
}
trap cleanup EXIT

step "the stack (without CrowdSec: it would ban the runner for the attacks of the set)"
"${compose[@]}" up -d --no-build nginxions openappsec test-upstream
for i in $(seq 1 90); do
  state=$(docker inspect -f '{{.State.Health.Status}}' "$("${compose[@]}" ps -q nginxions)" 2> /dev/null || true)
  [ "$state" = healthy ] && break
  [ "$i" = 90 ] && fail "nginxions is not healthy: $state"
  sleep 2
done

step "set up: admin, site train.local, default policy prevent, sources by X-Forwarded-For"
for i in $(seq 1 60); do
  curl -sk --max-time 5 "$ADMIN/api/" | grep -q '"status": *"OK"' && break
  [ "$i" = 60 ] && fail "admin API did not become ready"
  sleep 2
done
password="nginxions-train-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
api "$ADMIN/api/users" -d "{\"name\": \"Admin\", \"nickname\": \"admin\", \"email\": \"admin@nginxions.test\",
  \"auth\": {\"type\": \"password\", \"secret\": \"$password\"}}" > /dev/null
api "$ADMIN/api/tokens" -d "{\"identity\": \"admin@nginxions.test\", \"secret\": \"$password\"}" > /dev/null
# no exploit filter of nginx: only the model decides
api "$ADMIN/api/nginx/proxy-hosts" -d '{"domain_names": ["train.local"], "forward_scheme": "http",
  "forward_host": "test-upstream", "forward_port": "80", "block_exploits": false}' > /dev/null
xff=$(api "$ADMIN/api/nginxions/waf/policy/objects" -d '{"kind": "source_identifiers", "name": "train-xff",
  "spec": {"sourcesIdentifiers": [{"identifier": "headerkey", "value": ["x-forwarded-for"]}]}}' | jq -r .id)
# prevent, not prevent-learn: learning would change the verdicts while the set is sent
policy=$(api "$ADMIN/api/nginxions/waf/policy/objects" | jq -c --argjson xff "$xff" \
  '(.policy // {}) + {mode: "prevent", sourceIdentifiers: $xff} | with_entries(select(.value != null))')
api -X PUT "$ADMIN/api/nginxions/waf/policy/default" -d "$policy" > /dev/null
api -X POST "$ADMIN/api/nginxions/waf/policy/apply" > /dev/null
wait_verdicts
api "$ADMIN/api/nginxions/waf/policy" > "$work/policy.json"
docker cp "$("${compose[@]}" ps -q openappsec):/etc/cp/conf/waap/waap.data" "$work/waap-stock.data"
grep -q '"waap_scores"' "$work/waap-stock.data" || fail "no stock model in the agent"

step "the stock model: every request of the set"
"$PYTHON" model/replay.py --samples "$samples" --workers "$WORKERS" --target "$SITE" --out "$work/verdicts-stock.jsonl"
sleep 2
mv "$NGINXIONS_FEATURES_DIR"/*.jsonl "$work/dump-stock/" 2> /dev/null || fail "the agent wrote no features (patch 0005?)"

step "training"
"$PYTHON" model/train.py --samples "$samples" --dump "$work/dump-stock" --verdicts "$work/verdicts-stock.jsonl" \
  --base "$work/waap-stock.data" --name "$MODEL_NAME" --out "$work/out"

step "install the new model like an administrator (WAF -> Agent -> model), the agent restarts"
curl -sS --fail-with-body --max-time 300 -k -b "$JAR" -X PUT -H 'Content-Type: application/octet-stream' \
  --data-binary "@$work/out/open-appsec-advanced-model.tgz" "$ADMIN/api/nginxions/waf/agent/model?apply=true" > /dev/null
for i in $(seq 1 90); do
  docker exec "$("${compose[@]}" ps -q openappsec)" head -c 200 /etc/cp/conf/waap/waap.data 2> /dev/null \
    | grep -qF "NginxionS $MODEL_NAME" && break
  [ "$i" = 90 ] && fail "the agent did not take the new model"
  sleep 2
done
wait_verdicts
# the rows of the probes stay (sample "probe", not in the set): the agent keeps its files open, a file removed
# now would take everything it writes after

step "the new model: the held-out part"
"$PYTHON" model/replay.py --samples "$samples" --split test --workers "$WORKERS" --target "$SITE" \
  --out "$work/verdicts-new.jsonl"
sleep 2
mkdir -p "$work/dump-new"
mv "$NGINXIONS_FEATURES_DIR"/*.jsonl "$work/dump-new/" 2> /dev/null || fail "the agent wrote no features with the new model"

step "comparison and the release gate"
"$PYTHON" model/evaluate.py --samples "$samples" --stock "$work/verdicts-stock.jsonl" \
  --candidate "$work/verdicts-new.jsonl" --dump "$work/dump-new" --stock-dump "$work/dump-stock" --model "$work/out/waap.data" \
  --card "$work/out/model-card.json" --summary "$work/report.md" --out "$work/metrics.json"
