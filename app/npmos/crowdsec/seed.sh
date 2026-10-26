#!/bin/sh
# Builds an offline CrowdSec seed inside a crowdsecurity/crowdsec build stage (see app/Dockerfile).
# Output: /seed/etc (full /etc/crowdsec with hub index, hub content and installed items)
#         /seed/data (/var/lib/crowdsec/data with the data files hub items need).
# npmos-init copies it into the crowdsec volumes on first start, so the unmodified official
# image starts and installs hub items without internet.
#
# Env: HUB_BRANCH, HUB_ITEMS ("type item item; type item"), HUB_URL_TEMPLATE (optional mirror),
#      /run/secrets/ca_bundle (optional build secret for TLS-intercepting proxies).
set -eu

[ -s /run/secrets/ca_bundle ] && export SSL_CERT_FILE=/run/secrets/ca_bundle

mkdir -p /etc/crowdsec /var/lib/crowdsec/data
cp -a /staging/etc/crowdsec/. /etc/crowdsec/
cp -a /staging/var/lib/crowdsec/data/. /var/lib/crowdsec/data/

# fixed branch: cscli does not ask version.crowdsec.net which hub branch to use
yq e -i '.cscli.hub_branch = strenv(HUB_BRANCH)' /etc/crowdsec/config.yaml
if [ -n "${HUB_URL_TEMPLATE:-}" ]; then
  yq e -i '.cscli.__hub_url_template__ = strenv(HUB_URL_TEMPLATE)' /etc/crowdsec/config.yaml
fi

cscli hub update --with-content
echo "$HUB_ITEMS" | tr ';' '\n' | while read -r type items; do
  # shellcheck disable=SC2086
  [ -z "$type" ] || cscli "$type" install $items
done

yq e -i 'del(.cscli.__hub_url_template__)' /etc/crowdsec/config.yaml

mkdir -p /seed
cp -a /etc/crowdsec /seed/etc
cp -aL /var/lib/crowdsec/data /seed/data
rm -f /seed/data/crowdsec.db*
chmod -R a+rX /seed
