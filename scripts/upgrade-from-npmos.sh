#!/bin/sh
# Moves the data of a stack of the time the project was called NPMOS (compose project "npmos", volumes npmos_*)
# to NginxionS (project "nginxions", volumes nginxions_*). The old volumes are copied, not changed: delete them
# yourself once NginxionS runs (docker volume rm $(docker volume ls -q --filter name=^npmos_)).
#
#   docker compose -p npmos -f deploy/compose.yaml down     # the old stack, with its compose file of that time
#   scripts/upgrade-from-npmos.sh
#   docker compose -f deploy/compose.yaml up -d
#
# What the containers then do themselves: the backend renames the tables and migrations of the database
# (nginxions/backend/nginxions/rename.js), the nginxions container moves /data/npmos to /data/nginxions.
set -eu

OLD=npmos
NEW=nginxions
PG_IMAGE="docker.io/library/postgres:${POSTGRES_VERSION:-18.6-alpine}"
ALPINE="docker.io/library/alpine:3.22"

fail() { echo "FAIL: $*" >&2; exit 1; }

docker volume inspect "${OLD}_postgres-data" > /dev/null 2>&1 || fail "no volume ${OLD}_postgres-data: nothing to upgrade"
if [ -n "$(docker ps -q --filter "label=com.docker.compose.project=$OLD")" ]; then
  fail "the stack $OLD is running: stop it first (docker compose -p $OLD -f deploy/compose.yaml down)"
fi

for old in $(docker volume ls -q --filter "name=^${OLD}_"); do
  name=${old#"${OLD}_"}
  # tmpfs of the agent: nothing to keep, compose creates it with its options
  [ "$name" = appsec-shm ] && continue
  new="${NEW}_$(echo "$name" | sed "s/^${OLD}-/${NEW}-/")"
  if docker volume inspect "$new" > /dev/null 2>&1; then
    echo "skip $old: $new exists"
    continue
  fi
  echo "copy $old -> $new"
  docker volume create "$new" > /dev/null
  docker run --rm -v "$old:/from:ro" -v "$new:/to" "$ALPINE" cp -a /from/. /to/
done

echo "secrets: names of NginxionS"
docker run --rm -v "${NEW}_secrets:/s" "$ALPINE" sh -eu -c "
  [ -d /s/$OLD ] && [ ! -e /s/$NEW ] && mv /s/$OLD /s/$NEW
  [ -f /s/postgres/${OLD}_db_password ] && mv /s/postgres/${OLD}_db_password /s/postgres/${NEW}_db_password
  [ -f /s/crowdsec/bouncer_key_$OLD ] && mv /s/crowdsec/bouncer_key_$OLD /s/crowdsec/bouncer_key_$NEW
  true"

echo "postgres: role and database $OLD -> $NEW"
docker run -d --name "${NEW}-upgrade-pg" -v "${NEW}_postgres-data:/var/lib/postgresql" \
  -v "${NEW}_secrets:/s:ro" "$PG_IMAGE" > /dev/null
trap 'docker rm -f "${NEW}-upgrade-pg" > /dev/null 2>&1 || true' EXIT
i=0
until docker exec "${NEW}-upgrade-pg" pg_isready -q -U postgres 2> /dev/null; do
  i=$((i + 1))
  [ "$i" -lt 60 ] || fail "postgres did not start"
  sleep 1
done
sleep 2
docker exec "${NEW}-upgrade-pg" sh -eu -c "
  pw=\$(cat /s/postgres/${NEW}_db_password)
  psql -v ON_ERROR_STOP=1 -U postgres -d postgres -v pw=\"\$pw\" <<'SQL'
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$OLD';
ALTER DATABASE $OLD RENAME TO $NEW;
ALTER ROLE $OLD RENAME TO $NEW;
ALTER ROLE $NEW PASSWORD :'pw';
SQL"
echo "OK: start NginxionS: docker compose -f deploy/compose.yaml up -d"
