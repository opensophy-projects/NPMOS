# syntax=docker/dockerfile:1.28
# NginxionS open-appsec: one image, one container (nginxions-openappsec) with everything of the agent side, built from
# source at pinned commits (sources.env):
#   - the agent (github.com/openappsec/openappsec) with the patches of agent/patches;
#   - its shared storage (smartsync-shared-files) and tuning (smartsync-tuning) services, Go, go-service/patches;
#   - nginxions-control (nginxions/backend/nginxions/control, build context "control"): the Docker API for the GUI.
# nginxions-openappsec.sh starts and keeps them running. The container owns the network namespace nginxions joins, so
# the services listen on 127.0.0.1 ports there (port 80 is nginx's): shared storage 7811, tuning 7813, control 7080.
#
#   docker build --build-context control=nginxions/backend/nginxions/control -t nginxions-openappsec deploy/openappsec
#
# Base images pinned by digest (Renovate raises them). Alpine is the current release for the agent too: its CMake 4
# rejects the cmake_minimum_required (2.8.4) of the open-appsec sources, -DCMAKE_POLICY_VERSION_MINIMUM=3.5 lets it
# build them (built and checked on Alpine 3.24, GCC 15). The old Alpine 3.22 carried curl, zlib and sqlite with known
# vulnerabilities into the image.
# Go of the shared storage and tuning: their sources ask for 1.18, which has long been out of support (every CVE of
# its standard library since 2023). They build unchanged on a current release.
ARG OPENAPPSEC_REF=634f840534e07952b1a449079a0d1b2e885c6aec
ARG SHARED_FILES_REF=
ARG TUNING_REF=
# the runtime base of the final stage: the agent built here, or an image of it (a quick local rebuild)
ARG AGENT_RUNTIME=agent

# ---------------------------------------------------------------- agent
FROM docker.io/library/alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS agent-build
RUN apk add --no-cache build-base cmake git python3 bash linux-headers \
        boost-dev openssl-dev pcre2-dev libxml2-dev gtest-dev curl-dev hiredis-dev redis \
        libmaxminddb-dev yq brotli-dev zlib-dev
ARG OPENAPPSEC_REF
ADD --keep-git-dir=true https://github.com/openappsec/openappsec.git#${OPENAPPSEC_REF} /src
WORKDIR /src
# NginxionS patches (see each file): local-only hybrid mode without Fog registration; rate limits for hosts of the
# local policy (no scheme); no Fog reconnection after a policy update in local-only mode; host:port of services;
# the feature dump for training; rate limit rules of the local policy (it writes no "action" and "match")
COPY agent/patches/ /patches/
RUN git apply --verbose /patches/*.patch
# The model of the image: the advanced model of Check Point (agent/waap.data, "Advanced model, V2.0", its license
# inside the file) in place of the basic model of the sources, as its README says for a build of the agent. A model
# uploaded in WAF -> Agent replaces it at the start of the agent; removing that one brings this one back.
COPY agent/waap.data components/security_apps/waap/resources/waap.data
# Request headers every browser sends (Sec-Fetch-*, Priority, client hints) are not in the list of clean
# headers of the agent's signatures: the model takes "Sec-Fetch-Dest: style" for XSS and refuses every
# stylesheet Chrome loads. waap-headers.json adds them with strict patterns; another value is scanned as before.
COPY agent/waap-headers.json /patches/waap-headers.json
COPY agent/merge-headers.py /patches/merge-headers.py
RUN python3 /patches/merge-headers.py
RUN cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_INSTALL_PREFIX=build_out . && \
    make -j"$(nproc)" install && \
    make package && \
    mkdir -p /out/nano-service-installers && \
    cp build_out/install-*.sh /out/nano-service-installers/ && \
    cp build_out/entry.sh build_out/self_managed_openappsec_manifest.json /out/ && \
    ls -la /out /out/nano-service-installers

# the runtime of the agent (as the upstream image: /entry.sh and /nano-service-installers/*.sh)
FROM docker.io/library/alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS agent
ENV OPENAPPSEC_NANO_AGENT=TRUE
RUN apk upgrade --no-cache -a && \
    apk add --no-cache busybox zlib brotli brotli-dev bash libstdc++ boost icu-libs curl \
        libunwind gdb libxml2 pcre2 ca-certificates coreutils
COPY --from=agent-build /out/self_managed_openappsec_manifest.json /tmp/self_managed_openappsec_manifest.json
COPY --from=agent-build /out/nano-service-installers/ /nano-service-installers/
COPY --from=agent-build /out/entry.sh /entry.sh
RUN chmod +x /entry.sh /nano-service-installers/* && ln -s entry.sh cp-nano-agent

# ---------------------------------------------------------------- shared storage and tuning (Go)
# the same binaries and configs as their upstream images; modules are vendored under dependencies/
FROM docker.io/library/golang:1.27-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS go-build
RUN apk add --no-cache patch
ENV GOMODCACHE=/vendor CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local
COPY go-service/patches/ /patches/
# libraries raised over the ones of the sources: those have known vulnerabilities (Trivy, docs/DEVSECOPS.md); the
# Kubernetes client of tuning (its CRD listener, unused by NginxionS) to the last patch of its 0.17 line
ARG GO_UPGRADES="golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2 golang.org/x/net@v0.62.0 golang.org/x/text@v0.43.0 golang.org/x/oauth2@v0.37.0 github.com/sirupsen/logrus@v1.10.2 k8s.io/apimachinery@v0.17.16 k8s.io/client-go@v0.17.16 k8s.io/api@v0.17.16"

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
# Node.js for nginxions-control
RUN apk add --no-cache nodejs
COPY --from=shared-storage /out/ /opt/appsec-shared-storage/
COPY --from=tuning /out/ /opt/appsec-tuning/
COPY --from=control server.js watchdog.js /opt/nginxions-control/
RUN printf '{"type": "module"}\n' > /opt/nginxions-control/package.json && mkdir -p /db
# the settings of WAF -> Agent (fail-open), applied at every start of the agent; then the services
COPY agent/nginxions-entry.sh /nginxions-entry.sh
COPY nginxions-openappsec.sh /nginxions-openappsec.sh
RUN chmod 755 /nginxions-entry.sh /nginxions-openappsec.sh
LABEL org.opencontainers.image.source="https://github.com/opensophy-projects/NPMOS" \
      org.opencontainers.image.description="open-appsec agent, its learning services and nginxions-control for NginxionS"
# healthy while nginxions-control answers, or, without the Docker socket (no control), while the agent listens;
# nginxions-openappsec.sh keeps every service running
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/bin/sh", "-c", "wget -q -T 4 -O /dev/null http://127.0.0.1:7080/healthz || nc -z -w 4 127.0.0.1 7777"]
# root: the nano agent of open-appsec runs as root (its shared memory and IPC with the attachment of nginx), and
# nginxions-control reads the Docker socket; its own services listen on 127.0.0.1 only
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["/nginxions-openappsec.sh"]
