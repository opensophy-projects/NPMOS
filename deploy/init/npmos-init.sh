#!/bin/sh
# Generates NPMOS stack secrets once (existing secrets are never overwritten)
# and pre-creates volume subdirectories that other services mount by subpath.
# Layout (one directory per consumer, mounted via volume subpath):
#   postgres/{postgres,npmos_db,appsec_db}_password
#   npmos/db_password  npmos/bouncer_key
#   appsec/db_password
#   crowdsec/bouncer_key
set -eu
umask 077

gen() {
  [ -s "$1" ] || openssl rand -hex 32 > "$1"
}

mkdir -p /secrets/postgres /secrets/npmos /secrets/appsec /secrets/crowdsec

gen /secrets/postgres/postgres_password
gen /secrets/postgres/npmos_db_password
gen /secrets/postgres/appsec_db_password
gen /secrets/crowdsec/bouncer_key

cp /secrets/postgres/npmos_db_password /secrets/npmos/db_password
cp /secrets/postgres/appsec_db_password /secrets/appsec/db_password
cp /secrets/crowdsec/bouncer_key /secrets/npmos/bouncer_key

# Consumers run as different users (postgres uid 70, tuning-svc appuser, crowdsec and npmos root).
# Each container mounts only its own subdirectory, so world-readable files are not shared further.
chmod 755 /secrets/postgres /secrets/npmos /secrets/appsec /secrets/crowdsec
chmod 444 /secrets/*/*
# CrowdSec mounts npmos-data/nginx/logs by subpath; it must exist before npmos first starts
mkdir -p /npmos-data/nginx/logs

echo "npmos-init: ready"
