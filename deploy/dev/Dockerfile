# Fast dev image: upstream NPMplus image of the same subtree tag + our backend, rootfs and
# the offline CrowdSec seed. Builds in seconds. The production image is built from npmos/Dockerfile (CI).
# Keep NPMPLUS_BASE equal to the tag npmos/ was last synced to (see CLAUDE.md).
ARG NPMPLUS_BASE=docker.io/zoeyvid/npmplus:2026-10-22-r1
ARG CROWDSEC_VERSION=v1.8.1

FROM docker.io/crowdsecurity/crowdsec:${CROWDSEC_VERSION} AS crowdsec-seed
ARG HUB_BRANCH=master
ARG HUB_ITEMS="parsers crowdsecurity/docker-logs crowdsecurity/cri-logs; collections ZoeyVid/npmplus crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules"
ARG HUB_URL_TEMPLATE=
COPY crowdsec-seed/seed.sh /seed.sh
RUN --mount=type=secret,id=ca_bundle,required=false sh /seed.sh

# Backend dependencies NPMOS adds to upstream's (node_modules of the upstream image lack them).
# Versions come from our package.json; all of them are pure JS without dependencies of their own.
FROM docker.io/library/node:24-alpine AS backend-deps
ARG NPMOS_BACKEND_DEPS="yaml"
COPY backend/package.json /src/package.json
WORKDIR /deps
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -f /run/secrets/ca_bundle ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca_bundle; fi && \
    for dep in $NPMOS_BACKEND_DEPS; do \
      echo "$dep@$(node -p "require('/src/package.json').dependencies['$dep']")"; \
    done | xargs npm install --no-save --no-package-lock --omit=dev --ignore-scripts

FROM ${NPMPLUS_BASE}
COPY backend /app
COPY --from=backend-deps /deps/node_modules/ /app/node_modules/
COPY rootfs /
COPY --from=crowdsec-seed /seed /opt/npmos/crowdsec-seed
RUN sed -i "s|placeholder|$(jq -r .version /app/package.json)|g" /usr/local/nginx/conf/conf.d/crowdsec.conf.disabled && \
    chmod +x /usr/local/bin/*.sh
