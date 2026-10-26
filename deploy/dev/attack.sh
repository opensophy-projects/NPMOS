#!/bin/sh
# Sends a mix of benign and malicious requests to a proxy host, for WAF testing.
# TARGET is the NPMOS http endpoint, HOST the proxy host domain.
TARGET="${TARGET:-http://npmos}"
HOST="${HOST:-test.local}"
INTERVAL="${INTERVAL:-2}"

while true; do
  for path in \
    "/" \
    "/?q=hello" \
    "/?id=1%27%20OR%20%271%27=%271" \
    "/?q=%3Cscript%3Ealert(1)%3C/script%3E" \
    "/?file=../../../../etc/passwd" \
    "/?cmd=;cat%20/etc/passwd"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$TARGET$path")
    echo "$(date +%T) $code $path"
  done
  sleep "$INTERVAL"
done
