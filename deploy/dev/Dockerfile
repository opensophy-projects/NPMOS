# Fast dev image: upstream NPMplus image of the same subtree tag + our backend, rootfs and
# the offline CrowdSec seed. Builds in seconds. The production image is built from nginxions/Dockerfile (CI).
# Keep the NPMplus image of the last stage equal to the tag nginxions/ was last synced to (see CLAUDE.md). Images are
# pinned by digest (OpenSSF Scorecard); CI checks the tag of CrowdSec against deploy/.env.
FROM docker.io/crowdsecurity/crowdsec:v1.8.2@sha256:65b74942f7e7ed5c60fde4ac15fc4ba715904c398c8b16dd451f4907d90347d4 AS crowdsec-seed
ARG HUB_BRANCH=master
ARG HUB_ITEMS="parsers crowdsecurity/docker-logs crowdsecurity/cri-logs; collections ZoeyVid/npmplus crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules crowdsecurity/appsec-bot-challenge-good-bots"
ARG HUB_URL_TEMPLATE=
COPY crowdsec-seed/seed.sh /seed.sh
RUN --mount=type=secret,id=ca_bundle,required=false sh /seed.sh

# Backend dependencies NginxionS adds to upstream's (node_modules of the upstream image lack them).
# Versions come from our package.json; all of them are pure JS without dependencies of their own.
FROM docker.io/library/node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS backend-deps
ARG NGINXIONS_BACKEND_DEPS="yaml nodemailer"
COPY backend/package.json /src/package.json
WORKDIR /deps
# the RUN below pipes: a failed step of it fails the build (hadolint DL4006)
SHELL ["/bin/ash", "-o", "pipefail", "-c"]
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -f /run/secrets/ca_bundle ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca_bundle; fi && \
    for dep in $NGINXIONS_BACKEND_DEPS; do \
      echo "$dep@$(node -p "require('/src/package.json').dependencies['$dep']")"; \
    done | xargs npm install --no-save --no-package-lock --omit=dev --ignore-scripts

FROM docker.io/zoeyvid/npmplus:2026-10-22-r1@sha256:244fbf14f0c8bfb969434bfacba14ba71f8eee9911a2466035e640d64e594178
COPY backend /app
COPY --from=backend-deps /deps/node_modules/ /app/node_modules/
COPY rootfs /
COPY --from=crowdsec-seed /seed /opt/nginxions/crowdsec-seed
RUN sed -i "s|placeholder|$(jq -r .version /app/package.json)|g" /usr/local/nginx/conf/conf.d/crowdsec.conf.disabled && \
    chmod +x /usr/local/bin/*.sh
# the check of the upstream image, stated here (KICS, Trivy DS-0026)
HEALTHCHECK CMD ["healthcheck.sh"]
