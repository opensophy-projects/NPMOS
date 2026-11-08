#!/bin/sh
# Runs once on an empty data directory (docker-entrypoint-initdb.d).
# nginxions  — NginxionS database.
# appsec — open-appsec tuning service; it creates its own events database, hence CREATEDB.
set -eu

nginxions_pw=$(cat /run/nginxions-secrets/nginxions_db_password)
appsec_pw=$(cat /run/nginxions-secrets/appsec_db_password)

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v nginxions_pw="$nginxions_pw" -v appsec_pw="$appsec_pw" <<'SQL'
CREATE ROLE nginxions LOGIN PASSWORD :'nginxions_pw';
CREATE DATABASE nginxions OWNER nginxions;
CREATE ROLE appsec LOGIN CREATEDB PASSWORD :'appsec_pw';
CREATE DATABASE appsec OWNER appsec;
SQL
