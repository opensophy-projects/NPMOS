# Fast dev image: upstream NPMplus image of the same subtree tag + our backend and rootfs.
# Builds in seconds. The production image is built from app/Dockerfile (CI).
# Keep NPMPLUS_BASE equal to the tag app/ was last synced to (see CLAUDE.md).
ARG NPMPLUS_BASE=docker.io/zoeyvid/npmplus:2026-10-14-r1
FROM ${NPMPLUS_BASE}
COPY backend /app
COPY rootfs /
RUN sed -i "s|placeholder|$(jq -r .version /app/package.json)|g" /usr/local/nginx/conf/conf.d/crowdsec.conf.disabled && \
    chmod +x /usr/local/bin/*.sh
