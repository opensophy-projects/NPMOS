# syntax=docker/dockerfile:1.7
# NPMOS open-appsec agent, built from source (github.com/openappsec/openappsec) at a pinned commit.
# Runtime layout matches the upstream image (build_system/docker/Dockerfile): /entry.sh and
# /nano-service-installers/*.sh, so the same compose settings and entrypoint work.
ARG ALPINE_VERSION=3.22
ARG OPENAPPSEC_REF=634f840534e07952b1a449079a0d1b2e885c6aec

FROM docker.io/library/alpine:${ALPINE_VERSION} AS build
RUN apk add --no-cache build-base cmake git python3 bash linux-headers \
        boost-dev openssl-dev pcre2-dev libxml2-dev gtest-dev curl-dev hiredis-dev redis \
        libmaxminddb-dev yq brotli-dev zlib-dev
ARG OPENAPPSEC_REF
ADD --keep-git-dir=true https://github.com/openappsec/openappsec.git#${OPENAPPSEC_REF} /src
WORKDIR /src
RUN cmake -DCMAKE_INSTALL_PREFIX=build_out . && \
    make -j"$(nproc)" install && \
    make package && \
    mkdir -p /out/nano-service-installers && \
    cp build_out/install-*.sh /out/nano-service-installers/ && \
    cp build_out/entry.sh build_out/self_managed_openappsec_manifest.json /out/ && \
    ls -la /out /out/nano-service-installers

FROM docker.io/library/alpine:${ALPINE_VERSION}
ENV OPENAPPSEC_NANO_AGENT=TRUE
RUN apk add --no-cache -u busybox zlib brotli brotli-dev bash libstdc++ boost icu-libs curl \
        libunwind gdb libxml2 pcre2 ca-certificates coreutils
COPY --from=build /out/self_managed_openappsec_manifest.json /tmp/self_managed_openappsec_manifest.json
COPY --from=build /out/nano-service-installers/ /nano-service-installers/
COPY --from=build /out/entry.sh /entry.sh
RUN chmod +x /entry.sh /nano-service-installers/* && ln -s entry.sh cp-nano-agent
LABEL org.opencontainers.image.source="https://github.com/opensophy-projects/npmos" \
      org.opencontainers.image.description="open-appsec agent built from source for NPMOS"
CMD ["/cp-nano-agent"]
