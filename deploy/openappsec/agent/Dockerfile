# syntax=docker/dockerfile:1.28
# NPMOS open-appsec agent, built from source (github.com/openappsec/openappsec) at a pinned commit.
# Runtime layout matches the upstream image (build_system/docker/Dockerfile): /entry.sh and
# /nano-service-installers/*.sh, so the same compose settings and entrypoint work.
# Patches in patches/ are applied to the sources before the build.
# Alpine 3.22: newer releases ship CMake 4, which rejects the cmake_minimum_required of the pinned
# open-appsec sources. Renovate does not bump it (renovate.json); raise it together with OPENAPPSEC_REF.
ARG ALPINE_VERSION=3.22
ARG OPENAPPSEC_REF=634f840534e07952b1a449079a0d1b2e885c6aec

FROM docker.io/library/alpine:${ALPINE_VERSION} AS build
RUN apk add --no-cache build-base cmake git python3 bash linux-headers \
        boost-dev openssl-dev pcre2-dev libxml2-dev gtest-dev curl-dev hiredis-dev redis \
        libmaxminddb-dev yq brotli-dev zlib-dev
ARG OPENAPPSEC_REF
ADD --keep-git-dir=true https://github.com/openappsec/openappsec.git#${OPENAPPSEC_REF} /src
WORKDIR /src
# NPMOS patches (see each file): local-only hybrid mode without Fog registration; rate limits for
# hosts of the local policy (no scheme); no Fog reconnection after a policy update in local-only mode
COPY patches/ /patches/
RUN git apply --verbose /patches/*.patch
# Request headers every browser sends (Sec-Fetch-*, Priority, client hints) are not in the list of clean
# headers of the agent's signatures: the model takes "Sec-Fetch-Dest: style" for XSS and refuses every
# stylesheet Chrome loads. waap-headers.json adds them with strict patterns; another value is scanned as before.
COPY waap-headers.json /patches/waap-headers.json
RUN python3 - <<'EOF'
import json
path = "components/security_apps/waap/resources/waap.data"
with open(path) as f:
    data = json.load(f)
with open("/patches/waap-headers.json") as f:
    extra = json.load(f)
headers = data["waap_signatures"]["headers_re"]
clash = sorted(set(headers) & set(extra))
if clash:
    raise SystemExit(f"waap-headers.json: already in the signatures: {clash}")
headers.update(extra)
with open(path, "w") as f:
    json.dump(data, f, indent=1)
EOF
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
# settings from the NPMOS GUI (CrowdSec, fail-open), then the upstream entrypoint
COPY npmos-entry.sh /npmos-entry.sh
RUN chmod +x /npmos-entry.sh
LABEL org.opencontainers.image.source="https://github.com/opensophy-projects/npmos" \
      org.opencontainers.image.description="open-appsec agent built from source for NPMOS"
CMD ["/npmos-entry.sh"]
