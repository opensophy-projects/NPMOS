# syntax=docker/dockerfile:1.28
# NPMOS open-appsec: one image, one container (npmos-openappsec) with everything of the agent side, built from
# source at pinned commits (sources.env):
#   - the agent (github.com/openappsec/openappsec) with the patches of agent/patches;
#   - its shared storage (smartsync-shared-files) and tuning (smartsync-tuning) services, Go, go-service/patches;
#   - npmos-control (npmos/backend/npmos/control, build context "control"): the Docker API for the GUI.
# npmos-openappsec.sh starts and keeps them running. The container owns the network namespace npmos joins, so
# the services listen on 127.0.0.1 ports there (port 80 is nginx's): shared storage 7811, tuning 7813, control 7080.
#
#   docker build --build-context control=npmos/backend/npmos/control -t npmos-openappsec deploy/openappsec
#
# Alpine 3.22 for the agent: newer releases (3.23+) ship CMake 4, which rejects the cmake_minimum_required (2.8.4) of
# the pinned open-appsec sources. Renovate does not bump it (renovate.json, checked in CI); raise it together with
# OPENAPPSEC_REF, after a build of the agent on the new release.
ARG ALPINE_VERSION=3.22
# Go of the shared storage and tuning: their sources ask for 1.18, which has long been out of support (every CVE of
# its standard library since 2023). They build unchanged on a current release.
ARG GO_VERSION=1.27
ARG OPENAPPSEC_REF=634f840534e07952b1a449079a0d1b2e885c6aec
ARG SHARED_FILES_REF=
ARG TUNING_REF=
# the runtime base of the final stage: the agent built here, or an image of it (a quick local rebuild)
ARG AGENT_RUNTIME=agent

# ---------------------------------------------------------------- agent
FROM docker.io/library/alpine:${ALPINE_VERSION} AS agent-build
RUN apk add --no-cache build-base cmake git python3 bash linux-headers \
        boost-dev openssl-dev pcre2-dev libxml2-dev gtest-dev curl-dev hiredis-dev redis \
        libmaxminddb-dev yq brotli-dev zlib-dev
ARG OPENAPPSEC_REF
ADD --keep-git-dir=true https://github.com/openappsec/openappsec.git#${OPENAPPSEC_REF} /src
WORKDIR /src
# NPMOS patches (see each file): local-only hybrid mode without Fog registration; rate limits for hosts of the
# local policy (no scheme); no Fog reconnection after a policy update in local-only mode; host:port of services
COPY agent/patches/ /patches/
RUN git apply --verbose /patches/*.patch
# Request headers every browser sends (Sec-Fetch-*, Priority, client hints) are not in the list of clean
# headers of the agent's signatures: the model takes "Sec-Fetch-Dest: style" for XSS and refuses every
# stylesheet Chrome loads. waap-headers.json adds them with strict patterns; another value is scanned as before.
COPY agent/waap-headers.json /patches/waap-headers.json
COPY agent/merge-headers.py /patches/merge-headers.py
RUN python3 /patches/merge-headers.py
RUN cmake -DCMAKE_INSTALL_PREFIX=build_out . && \
    make -j"$(nproc)" install && \
    make package && \
    mkdir -p /out/nano-service-installers && \
    cp build_out/install-*.sh /out/nano-service-installers/ && \
    cp build_out/entry.sh build_out/self_managed_openappsec_manifest.json /out/ && \
    ls -la /out /out/nano-service-installers

# the runtime of the agent (as the upstream image: /entry.sh and /nano-service-installers/*.sh)
FROM docker.io/library/alpine:${ALPINE_VERSION} AS agent
ENV OPENAPPSEC_NANO_AGENT=TRUE
RUN apk add --no-cache -u busybox zlib brotli brotli-dev bash libstdc++ boost icu-libs curl \
        libunwind gdb libxml2 pcre2 ca-certificates coreutils
COPY --from=agent-build /out/self_managed_openappsec_manifest.json /tmp/self_managed_openappsec_manifest.json
COPY --from=agent-build /out/nano-service-installers/ /nano-service-installers/
COPY --from=agent-build /out/entry.sh /entry.sh
RUN chmod +x /entry.sh /nano-service-installers/* && ln -s entry.sh cp-nano-agent

# ---------------------------------------------------------------- shared storage and tuning (Go)
# the same binaries and configs as their upstream images; modules are vendored under dependencies/
FROM docker.io/library/golang:${GO_VERSION}-alpine AS go-build
RUN apk add --no-cache patch
ENV GOMODCACHE=/vendor CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local
COPY go-service/patches/ /patches/
# libraries raised over the ones of the sources: those have known vulnerabilities (Trivy, docs/DEVSECOPS.md)
ARG GO_UPGRADES="golang.org/x/crypto@v0.58.0 golang.org/x/net@v0.62.0 golang.org/x/text@v0.43.0 golang.org/x/oauth2@v0.37.0 github.com/sirupsen/logrus@v1.10.2"

FROM go-build AS shared-storage
ARG SHARED_FILES_REF
ADD https://github.com/openappsec/smartsync-shared-files.git#${SHARED_FILES_REF} /app
WORKDIR /app
RUN for p in /patches/smartsync-shared-files/*.patch; do [ -e "$p" ] || continue; patch -p1 < "$p" || exit 1; done && \
    go get $GO_UPGRADES && go mod tidy && \
    go build -ldflags="-w -s" -a -installsuffix cgo -o /out/app ./cmd/server/ && cp -r configs /out/configs

FROM go-build AS tuning
ARG TUNING_REF
ADD https://github.com/openappsec/smartsync-tuning.git#${TUNING_REF} /app
WORKDIR /app
# tuning: no database password in its log
RUN for p in /patches/smartsync-tuning/*.patch; do [ -e "$p" ] || continue; patch -p1 < "$p" || exit 1; done && \
    go get $GO_UPGRADES && go mod tidy && \
    go build -ldflags="-w -s" -a -installsuffix cgo -o /out/app ./cmd/server/ && cp -r configs /out/configs && \
    { [ ! -d api ] || cp -r api /out/api; }

# ---------------------------------------------------------------- the image
FROM ${AGENT_RUNTIME}
# Node.js for npmos-control
RUN apk add --no-cache nodejs
COPY --from=shared-storage /out/ /opt/appsec-shared-storage/
COPY --from=tuning /out/ /opt/appsec-tuning/
COPY --from=control server.js watchdog.js /opt/npmos-control/
RUN printf '{"type": "module"}\n' > /opt/npmos-control/package.json && mkdir -p /db
# the settings of WAF -> Agent (fail-open), applied at every start of the agent; then the services
COPY agent/npmos-entry.sh /npmos-entry.sh
COPY npmos-openappsec.sh /npmos-openappsec.sh
RUN chmod 755 /npmos-entry.sh /npmos-openappsec.sh
LABEL org.opencontainers.image.source="https://github.com/opensophy-projects/npmos" \
      org.opencontainers.image.description="open-appsec agent, its learning services and npmos-control for NPMOS"
# root: the nano agent of open-appsec runs as root (its shared memory and IPC with the attachment of nginx), and
# npmos-control reads the Docker socket; its own services listen on 127.0.0.1 only
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["/npmos-openappsec.sh"]
