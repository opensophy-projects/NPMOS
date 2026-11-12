# syntax=docker/dockerfile:1.29
# NginxionS open-appsec: one image, one container (nginxions-openappsec) with everything of the agent side, built from
# the sources of NginxionS in openappsec/ (build context "openappsec"; upstream commits they started from: sources.env):
#   - the agent (openappsec/agent), the changes of NginxionS marked "NginxionS:" in its code;
#   - its shared storage (openappsec/smartsync-shared-files) and tuning (openappsec/smartsync-tuning) services, Go;
#   - nginxions-control (nginxions/backend/nginxions/control, build context "control"): the Docker API for the GUI.
# nginxions-openappsec.sh starts and keeps them running. The container owns the network namespace nginxions joins, so
# the services listen on 127.0.0.1 ports there (port 80 is nginx's): shared storage 7811, tuning 7813, control 7080.
#
#   docker build --build-context openappsec=openappsec --build-context control=nginxions/backend/nginxions/control \
#     -t nginxions-openappsec deploy/openappsec
#
# Base images pinned by digest (Renovate raises them). Alpine is the current release for the agent too: its CMake 4
# rejects the cmake_minimum_required (2.8.4) of the open-appsec sources, -DCMAKE_POLICY_VERSION_MINIMUM=3.5 lets it
# build them (built and checked on Alpine 3.24, GCC 15). The old Alpine 3.22 carried curl, zlib and sqlite with known
# vulnerabilities into the image.
# Go of the shared storage and tuning: their sources ask for 1.18, which has long been out of support (every CVE of
# its standard library since 2023). They build unchanged on a current release.
# the runtime base of the final stage: the agent built here, or an image of it (a quick local rebuild)
ARG AGENT_RUNTIME=agent

# ---------------------------------------------------------------- agent
FROM docker.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS agent-build
RUN apk add --no-cache build-base cmake git python3 bash linux-headers \
        boost-dev openssl-dev pcre2-dev libxml2-dev gtest-dev curl-dev hiredis-dev redis \
        libmaxminddb-dev yq brotli-dev zlib-dev
# changes of NginxionS in the agent (grep "NginxionS:"): no cloud at all (no registration, no Fog, no message or
# download to a host of open-appsec, no token for the local services); rate limits for hosts of the local policy (no
# scheme) and its rules (no "action" and "match"); host:port of services; the feature dump for training. Its model
# (components/security_apps/waap/resources/waap.data) is the advanced model of Check Point ("Advanced model, V2.0",
# its license inside the file) with the request headers of browsers (Sec-Fetch-*, Priority, client hints) among the
# clean headers of its signatures; a model uploaded in WAF -> Agent replaces it at the start of the agent.
COPY --from=openappsec agent/ /src/
WORKDIR /src
RUN cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_INSTALL_PREFIX=build_out . && \
    make -j"$(nproc)" install && \
    make package && \
    mkdir -p /out/nano-service-installers && \
    cp build_out/install-*.sh /out/nano-service-installers/ && \
    cp build_out/entry.sh build_out/self_managed_openappsec_manifest.json /out/ && \
    ls -la /out /out/nano-service-installers

# the runtime of the agent (as the upstream image: /entry.sh and /nano-service-installers/*.sh)
FROM docker.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS agent
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
FROM docker.io/library/golang:1.27-alpine@sha256:eb61c3873c97416fff0116553fff65d67a3549f72e11d9758849a689cdd8b523 AS go-build
# their libraries are raised in their go.mod over the ones of upstream (known vulnerabilities, docs/DEVSECOPS.md)
ENV GOMODCACHE=/vendor CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local

FROM go-build AS shared-storage
COPY --from=openappsec smartsync-shared-files/ /app/
WORKDIR /app
RUN go build -ldflags="-w -s" -a -installsuffix cgo -o /out/app ./cmd/server/ && cp -r configs /out/configs

FROM go-build AS tuning
# tuning: no database password in its log (NginxionS: in its code)
COPY --from=openappsec smartsync-tuning/ /app/
WORKDIR /app
RUN go build -ldflags="-w -s" -a -installsuffix cgo -o /out/app ./cmd/server/ && cp -r configs /out/configs && \
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
