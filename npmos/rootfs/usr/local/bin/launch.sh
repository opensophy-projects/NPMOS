#!/usr/bin/env sh

echo "
-------------------------------------
PUID:     $PUID
User ID:  $(id -u)
PGID:     $PGID
Group ID: $(id -g)
-------------------------------------
"

# NPMOS: local-first — no ACME account registration at startup (it contacted the ACME server on
# every start and blocked startup when offline). The backend registers on the first certificate
# request: npmos/backend/npmos/acme.js.

if [ "$ACME_OCSP_STAPLING" = "true" ]; then
    certbot-ocsp-fetcher.sh -c /data/tls/certbot/live -o /data/tls/certbot/live --no-reload-webserver --force-update || true
    echo
fi
if [ "$CUSTOM_OCSP_STAPLING" = "true" ]; then
    certbot-ocsp-fetcher.sh -c /data/tls/custom -o /data/tls/custom --no-reload-webserver --force-update || true
    echo
fi


if ! nginx -tq; then
    sleep inf
fi
if [ "$PHP83" = "true" ]; then
    if ! PHP_INI_SCAN_DIR=/data/php/83/conf.d php-fpm83 -c /data/php/83 -y /data/php/83/php-fpm.conf -FORt > /dev/null 2>&1; then
        PHP_INI_SCAN_DIR=/data/php/83/conf.d php-fpm83 -c /data/php/83 -y /data/php/83/php-fpm.conf -FORt
        sleep inf
    fi
fi
if [ "$PHP84" = "true" ]; then
    if ! PHP_INI_SCAN_DIR=/data/php/84/conf.d php-fpm84 -c /data/php/84 -y /data/php/84/php-fpm.conf -FORt > /dev/null 2>&1; then
        PHP_INI_SCAN_DIR=/data/php/84/conf.d php-fpm84 -c /data/php/84 -y /data/php/84/php-fpm.conf -FORt
        sleep inf
    fi
fi
if [ "$PHP85" = "true" ]; then
    if ! PHP_INI_SCAN_DIR=/data/php/85/conf.d php-fpm85 -c /data/php/85 -y /data/php/85/php-fpm.conf -FORt > /dev/null 2>&1; then
        PHP_INI_SCAN_DIR=/data/php/85/conf.d php-fpm85 -c /data/php/85 -y /data/php/85/php-fpm.conf -FORt
        sleep inf
    fi
fi


echo "Starting services..."
if [ "$PHP83" = "true" ]; then while true; do PHP_INI_SCAN_DIR=/data/php/83/conf.d php-fpm83 -c /data/php/83 -y /data/php/83/php-fpm.conf -FOR; done; fi &
if [ "$PHP84" = "true" ]; then while true; do PHP_INI_SCAN_DIR=/data/php/84/conf.d php-fpm84 -c /data/php/84 -y /data/php/84/php-fpm.conf -FOR; done; fi &
if [ "$PHP85" = "true" ]; then while true; do PHP_INI_SCAN_DIR=/data/php/85/conf.d php-fpm85 -c /data/php/85 -y /data/php/85/php-fpm.conf -FOR; done; fi &
if [ "$LOGROTATE" = "true" ]; then while true; do logrotate --verbose --state /data/nginx/logs/logrotate.state /etc/logrotate; sleep 25h; done; fi &
# shellcheck disable=SC2086
if [ "$GOA" = "true" ]; then set -f; while true; do if [ -s /data/nginx/logs/access.log ]; then goaccess --no-global-config --num-tests=0 --tz="$TZ" --time-format="%H:%M:%S" \
                    --date-format="%d/%b/%Y" --log-format='[%d:%t %^] %v %h %T "%r" %s %b %b %R %u' --unix-socket=/run/goaccess.sock --log-file=/data/nginx/logs/access.log \
                    --real-time-html --output=/tmp/goa/index.html --db-path=/data/goaccess/data --restore --persist \
                    --browsers-file=/etc/goaccess/browsers.list --browsers-file=/etc/goaccess/podcast.list $GOACLA; else sleep 10s; fi; done; fi &
while true; do
  sleep 10s
  if [ -s "/data/tls/ech/cron.sh" ]; then
    chmod +x /data/tls/ech/cron.sh
    /data/tls/ech/cron.sh
    sed -i "s|#ssl_ech_file|ssl_ech_file|g" /usr/local/nginx/conf/nginx.conf
    nginx -s reload
  elif grep -q '^[^#]*ssl_ech_file' /usr/local/nginx/conf/nginx.conf; then
    sed -i "s|ssl_ech_file|#ssl_ech_file|g" /usr/local/nginx/conf/nginx.conf
    nginx -s reload
  fi
  sleep "$ECH_ROTATION_INTERVAL"h
done &
while true; do nginx -e stderr; done &
while true; do index.js; done
