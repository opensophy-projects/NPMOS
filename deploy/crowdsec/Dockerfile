# NPMOS CrowdSec: upstream image + an offline hub snapshot.
# The hub index and the content of every hub item are baked in at build time, and the
# items NPMOS needs are pre-installed, so the container starts and installs hub items
# without internet (upstream docker_start.sh otherwise exits when the hub is unreachable).
ARG CROWDSEC_VERSION=v1.8.1
FROM docker.io/crowdsecurity/crowdsec:${CROWDSEC_VERSION}

# Pre-installed on first start (copied from /staging/etc/crowdsec into the config volume).
# crowdsecurity/docker-logs and cri-logs are installed unconditionally by docker_start.sh.
ARG HUB_ITEMS="parsers crowdsecurity/docker-logs crowdsecurity/cri-logs; collections ZoeyVid/npmplus"

# Fixed hub branch: cscli does not ask version.crowdsec.net which branch to use
ARG HUB_BRANCH=master

# Optional hub mirror for the build only, e.g. https://raw.githubusercontent.com/crowdsecurity/hub/%s/%s
# (a mirror without per-item content: only HUB_ITEMS are then available offline)
ARG HUB_URL_TEMPLATE=

# ca_bundle: optional build secret for builds behind a TLS-intercepting proxy
RUN --mount=type=secret,id=ca_bundle,required=false \
    set -e; \
    if [ -s /run/secrets/ca_bundle ]; then export SSL_CERT_FILE=/run/secrets/ca_bundle; fi; \
    cscli() { command cscli -c /staging/etc/crowdsec/config.yaml "$@"; }; \
    sed -i 's|/etc/crowdsec|/staging/etc/crowdsec|g; s|/var/lib/crowdsec/data|/staging/var/lib/crowdsec/data|g' /staging/etc/crowdsec/config.yaml; \
    yq e -i '.cscli.hub_branch = strenv(HUB_BRANCH)' /staging/etc/crowdsec/config.yaml; \
    if [ -n "$HUB_URL_TEMPLATE" ]; then yq e -i '.cscli.__hub_url_template__ = strenv(HUB_URL_TEMPLATE)' /staging/etc/crowdsec/config.yaml; fi; \
    cscli hub update --with-content; \
    echo "$HUB_ITEMS" | tr ';' '\n' | while read -r type items; do \
        [ -n "$type" ] && cscli "$type" install $items; \
    done; \
    yq e -i 'del(.cscli.__hub_url_template__)' /staging/etc/crowdsec/config.yaml; \
    sed -i 's|/staging/etc/crowdsec|/etc/crowdsec|g; s|/staging/var/lib/crowdsec/data|/var/lib/crowdsec/data|g' /staging/etc/crowdsec/config.yaml; \
    chmod -R a+rX /staging/etc/crowdsec/hub; \
    find /staging/etc/crowdsec -type l | while read -r l; do \
        t=$(readlink "$l"); \
        case "$t" in /staging/*) ln -sfn "${t#/staging}" "$l" ;; esac; \
    done
