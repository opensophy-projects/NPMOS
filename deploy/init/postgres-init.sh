#!/bin/sh
# Runs once on an empty data directory (docker-entrypoint-initdb.d).
# npmos  — NPMOS database.
# appsec — open-appsec tuning service; it creates its own events database, hence CREATEDB.
set -eu

npmos_pw=$(cat /run/npmos-secrets/npmos_db_password)
appsec_pw=$(cat /run/npmos-secrets/appsec_db_password)

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v npmos_pw="$npmos_pw" -v appsec_pw="$appsec_pw" <<'SQL'
CREATE ROLE npmos LOGIN PASSWORD :'npmos_pw';
CREATE DATABASE npmos OWNER npmos;
CREATE ROLE appsec LOGIN CREATEDB PASSWORD :'appsec_pw';
CREATE DATABASE appsec OWNER appsec;
SQL
