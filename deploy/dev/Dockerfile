# Fast dev image: upstream NPMplus image of the same subtree tag + our backend, rootfs and
# the offline CrowdSec seed. Builds in seconds. The production image is built from app/Dockerfile (CI).
# Keep NPMPLUS_BASE equal to the tag app/ was last synced to (see CLAUDE.md).
ARG NPMPLUS_BASE=docker.io/zoeyvid/npmplus:2026-10-22-r1
ARG CROWDSEC_VERSION=v1.8.1

FROM docker.io/crowdsecurity/crowdsec:${CROWDSEC_VERSION} AS crowdsec-seed
ARG HUB_BRANCH=master
ARG HUB_ITEMS="parsers crowdsecurity/docker-logs crowdsecurity/cri-logs; collections ZoeyVid/npmplus crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules"
ARG HUB_URL_TEMPLATE=
COPY npmos/crowdsec/seed.sh /seed.sh
RUN --mount=type=secret,id=ca_bundle,required=false sh /seed.sh

FROM ${NPMPLUS_BASE}
COPY backend /app
COPY rootfs /
COPY --from=crowdsec-seed /seed /opt/npmos/crowdsec-seed
RUN sed -i "s|placeholder|$(jq -r .version /app/package.json)|g" /usr/local/nginx/conf/conf.d/crowdsec.conf.disabled && \
    chmod +x /usr/local/bin/*.sh
