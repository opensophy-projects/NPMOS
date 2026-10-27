# syntax=docker/dockerfile:1.7
# NPMOS build of the open-appsec learning services (Go), from source at a pinned commit:
#   smartsync              REPO=https://github.com/openappsec/smartsync.git
#   smartsync-shared-files REPO=https://github.com/openappsec/smartsync-shared-files.git
#   smartsync-tuning       REPO=https://github.com/openappsec/smartsync-tuning.git
# Same binary and configs as upstream build/package/Dockerfile; differences:
#   - current Alpine runtime instead of 3.13;
#   - /npmos-entry.sh: VAR_FILE=/path sets VAR from a file (secrets without shell wrappers);
#   - /db owned by appuser, so shared-storage does not need to run as root.
ARG GO_VERSION=1.18
ARG ALPINE_VERSION=3.24

FROM docker.io/library/golang:${GO_VERSION}-alpine AS build
ARG REPO
ARG REF
ADD ${REPO}#${REF} /app
WORKDIR /app
# modules are vendored under dependencies/ (go.mod replace directives)
ENV GOMODCACHE=/vendor
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -a -installsuffix cgo -o /go/bin/app ./cmd/server/

FROM docker.io/library/alpine:${ALPINE_VERSION}
RUN apk add --no-cache libcap && adduser -D -g '' appuser && mkdir /db && chown appuser:appuser /db
COPY --from=build /go/bin/app /go/bin/app
COPY --from=build /app/configs/ /configs/
COPY npmos-entry.sh /npmos-entry.sh
RUN setcap CAP_NET_BIND_SERVICE=+eip /go/bin/app && chmod 755 /npmos-entry.sh
USER appuser
ENV APPSEC_MODE=standalone
EXPOSE 80 8080
LABEL org.opencontainers.image.source="https://github.com/opensophy-projects/npmos"
ENTRYPOINT ["/npmos-entry.sh", "/go/bin/app"]
