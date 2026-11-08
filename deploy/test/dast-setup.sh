#!/bin/sh
# Sets up a fresh stack for DAST (scripts/test-dast.sh) the way an administrator would through the interface: the
# first admin, a root CA and a server certificate of the PKI of NPMOS, a proxy host dast.local with TLS, HTTP/2,
# HSTS and the exploit filter in front of test-upstream. Leaves the session cookie in /state/cookie for the
# scanners of the API.
set -eu

ADMIN="https://npmos:81"
EMAIL="admin@npmos.test"
PASSWORD="npmos-dast-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
JAR=/state/cookies
CURL="curl -sS --fail-with-body --max-time 30 -k -b $JAR -c $JAR"

step() { echo "==> $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
json_id() { tr -d ' \n' | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*$'; }
api_json() { $CURL -H 'Content-Type: application/json' "$@"; }
# a JSON request whose answer is printed; a failure shows the status and the body of the answer
api_ok() {
  out=$(curl -sS --max-time 30 -k -b "$JAR" -c "$JAR" -w '\n%{http_code}' -H 'Content-Type: application/json' "$@")
  code=$(printf '%s' "$out" | tail -n 1)
  body=$(printf '%s' "$out" | sed '$d')
  case "$code" in
    2*) printf '%s' "$body" ;;
    *) fail "$1 -> $code: $body" ;;
  esac
}

rm -f "$JAR" /state/cookie
step "admin API is up"
for i in $(seq 1 60); do
  $CURL "$ADMIN/api/" 2> /dev/null | grep -q '"status": *"OK"' && break
  [ "$i" = 60 ] && fail "admin API did not become ready"
  sleep 2
done

step "the first admin, a session"
api_json "$ADMIN/api/users" -d "{\"name\": \"Admin\", \"nickname\": \"admin\", \"email\": \"$EMAIL\",
  \"auth\": {\"type\": \"password\", \"secret\": \"$PASSWORD\"}}" > /dev/null
api_json "$ADMIN/api/tokens" -d "{\"identity\": \"$EMAIL\", \"secret\": \"$PASSWORD\"}" > /dev/null

step "a root CA, a trust domain and a server certificate for dast.local (PKI of NPMOS)"
root_id=$(api_ok "$ADMIN/api/npmos/pki/cas" \
  -d '{"kind": "root", "name": "DAST Root", "subject": {"common_name": "DAST Root", "organization": "NPMOS"}}' | json_id)
[ -n "$root_id" ] || fail "root CA was not created"
ca_id=$(api_ok "$ADMIN/api/npmos/pki/cas" -d "{\"kind\": \"intermediate\", \"name\": \"DAST Servers\",
  \"parent_id\": $root_id, \"subject\": {\"common_name\": \"DAST Servers\", \"organization\": \"NPMOS\"}}" | json_id)
[ -n "$ca_id" ] || fail "trust domain was not created"
server=$(api_ok "$ADMIN/api/npmos/pki/certs" -d "{\"ca_id\": $ca_id, \"profile\": \"server\",
  \"subject\": {\"common_name\": \"dast.local\"}, \"sans\": {\"dns\": [\"dast.local\"]}, \"install\": true}")
cert_id=$(echo "$server" | tr -d ' \n' | grep -o '"certificate_id":[0-9]*' | grep -o '[0-9]*$')
[ -n "$cert_id" ] || fail "server certificate was not installed: $server"

step "a proxy host dast.local -> test-upstream: TLS forced, HTTP/2, HSTS, exploit filter"
api_ok "$ADMIN/api/nginx/proxy-hosts" -d "{\"domain_names\": [\"dast.local\"], \"forward_scheme\": \"http\",
  \"forward_host\": \"test-upstream\", \"forward_port\": \"80\", \"certificate_id\": $cert_id, \"ssl_forced\": true,
  \"http2_support\": true, \"hsts_enabled\": true, \"hsts_subdomains\": false, \"block_exploits\": true}" | json_id > /dev/null

step "the site answers through the proxy"
for i in $(seq 1 30); do
  body=$(curl -sS -k --max-time 10 --connect-to dast.local:443:npmos:443 https://dast.local/ 2> /dev/null || true)
  echo "$body" | grep -q '^Hostname:' && break
  [ "$i" = 30 ] && fail "dast.local did not answer: $body"
  sleep 2
done

# the cookie of the session (Netscape format of the jar: the value is the 7th field)
token=$(awk '$6 == "__Host-Http-token" { print $7 }' "$JAR")
[ -n "$token" ] || fail "no session cookie in the jar"
printf '%s' "$token" > /state/cookie
echo "OK: the stack is set up for DAST"
