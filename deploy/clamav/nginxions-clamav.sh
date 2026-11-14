#!/bin/sh
# NginxionS: the entrypoint of the clamav container (deploy/compose.yaml). clamd scans the uploads of the hosts with
# File Security in a practice of the WAF policy (nginxions/backend/nginxions/waf/files.js). Its signatures take about
# 1 GB of memory, so it runs only while a rule needs it: NginxionS writes the flag "enabled" into the control volume
# (/nginxions, read only here) and restarts this container. Without the flag the container only waits.
# Signature files uploaded in WAF -> Agent (/nginxions/db) replace those of the image at the start; freshclam (online
# updates, needs the internet) runs only when allowed there (/nginxions/freshclam).
set -eu

CTL=/nginxions

if [ ! -f "$CTL/enabled" ]; then
  echo "NginxionS: no practice of the WAF policy has File Security on, clamd does not run"
  trap 'exit 0' TERM INT
  while :; do sleep 3600 & wait $!; done
fi

for f in "$CTL"/db/*.cvd "$CTL"/db/*.cld "$CTL"/db/*.cud; do
  [ -f "$f" ] || continue
  echo "NginxionS: signatures $(basename "$f") uploaded in NginxionS"
  cp -f "$f" /var/lib/clamav/
done

if [ -f "$CTL/freshclam" ]; then
  echo "NginxionS: online updates of the signatures are on (freshclam)"
  export CLAMAV_NO_FRESHCLAMD=false
else
  export CLAMAV_NO_FRESHCLAMD=true
fi
export CLAMAV_NO_MILTERD=true
exec /init
