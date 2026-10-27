#!/bin/sh
# One-shot bootstrap of the NPMOS stack, runs from the npmos image before other services.
# Idempotent: existing secrets and volumes are never overwritten.
#
# 1. Secrets (one directory per consumer, mounted via volume subpath):
#      postgres/{postgres,npmos_db,appsec_db}_password
#      npmos/{db_password,cookie_secret,bouncer_key,control_token}
#      appsec/db_password
#      crowdsec/bouncer_key_npmos   (official image registers /run/secrets/bouncer_key_<name>)
#      control/control_token        (npmos-control; the backend gets a copy)
# 2. Pre-created directories that other services mount by subpath.
# 3. CrowdSec volumes seeded from the offline hub snapshot baked into the npmos image,
#    so the official crowdsec image starts without internet.
set -eu
umask 077

gen() {
  [ -s "$1" ] || openssl rand -hex 32 > "$1"
}

mkdir -p /secrets/postgres /secrets/npmos /secrets/appsec /secrets/crowdsec /secrets/control

gen /secrets/postgres/postgres_password
gen /secrets/postgres/npmos_db_password
gen /secrets/postgres/appsec_db_password
gen /secrets/npmos/cookie_secret
gen /secrets/crowdsec/bouncer_key_npmos
gen /secrets/control/control_token

cp /secrets/postgres/npmos_db_password /secrets/npmos/db_password
cp /secrets/postgres/appsec_db_password /secrets/appsec/db_password
cp /secrets/crowdsec/bouncer_key_npmos /secrets/npmos/bouncer_key
cp /secrets/control/control_token /secrets/npmos/control_token

# Consumers run as different users (postgres uid 70, tuning-svc appuser, crowdsec and npmos root).
# Each container mounts only its own subdirectory, so world-readable files are not shared further.
chmod 755 /secrets/postgres /secrets/npmos /secrets/appsec /secrets/crowdsec /secrets/control
chmod 444 /secrets/*/*

# CrowdSec mounts npmos-data/nginx/logs by subpath; it must exist before npmos first starts
mkdir -p /npmos-data/nginx/logs

seed=/opt/npmos/crowdsec-seed
if [ ! -e /crowdsec-conf/config.yaml ]; then
  cp -a "$seed/etc/." /crowdsec-conf/
  echo "npmos-init: CrowdSec config seeded from the offline hub snapshot"
fi
if [ -z "$(ls -A /crowdsec-data 2> /dev/null)" ]; then
  cp -a "$seed/data/." /crowdsec-data/
  echo "npmos-init: CrowdSec data seeded"
fi

# open-appsec agent installed before NPMOS_LOCAL_ONLY (phase 0) keeps the cloud Fog address in its
# config volume across upgrades; point it to the closed local port (see appsec-agent in compose.yaml)
agent_details=/appsec-conf/agent_details.json
if [ -s "$agent_details" ] && [ "$(jq -r '."Fog domain"' "$agent_details")" != 127.0.0.1 ]; then
  jq '."Fog domain" = "127.0.0.1" | ."Fog port" = 1 | ."Encrypted connection" = false' "$agent_details" > "$agent_details.tmp"
  mv "$agent_details.tmp" "$agent_details"
  echo "npmos-init: open-appsec agent switched to local-only"
fi

echo "npmos-init: ready"
