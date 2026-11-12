# syntax=docker/dockerfile:1.25.0@sha256:0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12
# NginxionS: must match CROWDSEC_VERSION in deploy/.env (checked in CI)
ARG CROWDSEC_VERSION=v1.8.2
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS nginx
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

ARG LUAJIT_INC=/usr/include/luajit-2.1
ARG LUAJIT_LIB=/usr/lib

ARG AWSLC_VER=683ebde4bf3bcc016a9a710ad6b49c0c91b59161 # v5.2.0

ARG NGINX_VER=aaecf65316bb4af1e4f12f6a8746da2ab278c967 # release-1.31.7
ARG DTR_VER=1.29.2
ARG RCP_VER=1.31.2
ARG ZNP_VER=1.30.0

ARG NB_VER=a71f9312c2deb28875acc7bacfdd5695a111aa53 # master
ARG NUB_VER=60bed634504967a323645f8f53566cca3f2c3f53 # main
ARG ZNM_VER=057a7d339af1111d04b5a9ac5ae9b0250d17cd94 # master
ARG NHUZFM_VER=37e77ed348c242e222f2ae2b02c2e445e0ee2dc6 # main
ARG NF_VER=047589e4dc0041517b8a47739fa960c430c4045e # v0.6.0
ARG HMNM_VER=0bf283ff92017acd616814b0e5153e0ccf93e2c9 # v0.40
ARG NDK_VER=bd44d16302273052d6005d7bdb55f74e23813de3 # v0.3.4
ARG LNM_VER=4b21d8f5fd3cc94fd25c530b3a61405af9666d0b # v0.10.31

ARG NJS_VER=ad60b62c3b4ca6339ca19c19ceed8c942dbe575d # 1.0.0
ARG NAL_VER=241200eac8e4acae74d353291bd27f79e5ca3dc4 # master
ARG VTS_VER=b2a036ab6c1ffd5615f9ea57d6710287590735cd # v0.2.5
ARG NNTLM_VER=3da77b0cb30e517dfee01d7e7f7d649144d24051 # master
ARG NHG2M_VER=cbaa35461c62a99d2577e6bae3273492502d8769 # 3.4

ARG OASA_VER=2f46293b32c58d5be250aa6d3bac0e4ba9260738 # main


WORKDIR /src
COPY patches/*.patch /src
COPY rootfs/usr/local/bin/git-clone-commit.sh /usr/local/bin/git-clone-commit.sh

RUN apk upgrade --no-cache -a && \
    apk add --no-cache git clang lld compiler-rt llvm-libunwind-dev libc++-dev linux-headers cmake ninja make llvm file \
                       libatomic_ops-dev pcre2-dev luajit-dev zlib-ng-dev brotli-dev zstd-dev libxslt-dev openldap-dev quickjs-ng-dev libmaxminddb-dev clang-dev

RUN for f in $(apk info --no-cache -qL libgcc-static libstdc++-dev); do rm /"$f"; done && \
    echo "-fuse-ld=lld --rtlib=compiler-rt --unwindlib=libunwind -stdlib=libc++ -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE" | tee /etc/clang*/*.cfg

ARG CC=clang
ARG CXX=clang++
ARG LD=ld.lld
ARG AR=llvm-ar

ARG FLAGS
ARG CFLAGS="$FLAGS -m64 -O3 -pipe -flto=full -ffunction-sections -fdata-sections -fno-math-errno -ffp-contract=fast -fstack-clash-protection -fstack-protector-strong -fzero-call-used-regs=used-gpr -fstrict-flex-arrays=3 -ftrivial-auto-var-init=zero -fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing -fno-semantic-interposition -fno-plt -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -Wformat=2 -Werror=format-security -Wno-sign-compare"
ARG CXXFLAGS="$CFLAGS"
ARG LDFLAGS="-m64 -Wl,-s -Wl,-O2 -Wl,--lto-O3 -Wl,--icf=safe -Wl,--gc-sections -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -Wl,--sort-common -Wl,--as-needed -Wl,-z,pack-relative-relocs -Wl,--no-copy-dt-needed-entries"

RUN git config --global advice.detachedHead false && \
    git config --global init.defaultBranch main

# NginxionS: git -C, cmake -S/-B, ninja -C and WORKDIR instead of cd in the RUNs (hadolint DL3003, Trivy DS-0013)
RUN git-clone-commit.sh https://github.com/aws/aws-lc "$AWSLC_VER" /src/aws-lc && \
    git -C /src/aws-lc apply /src/aws-lc-tls13-cipher-preference.patch && \
    cmake -S /src/aws-lc -B /src/aws-lc -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DDISABLE_GO=ON -DDISABLE_PERL=ON -DBUILD_TESTING=OFF && \
    ninja -C /src/aws-lc install

RUN git-clone-commit.sh https://github.com/nginx/nginx "$NGINX_VER" /src/nginx && \
    wget -q https://patch-diff.githubusercontent.com/raw/nginx/nginx/pull/689.patch -O /src/nginx/1.patch && \
    echo "73fdee62748f1624f87015a951a2480fd0d4fe566a81d92b852b51536d954b91  /src/nginx/1.patch" | sha256sum -c - && \
    git -C /src/nginx apply /src/nginx/1.patch && \
    wget -q https://patch-diff.githubusercontent.com/raw/nginx/nginx/pull/1333.patch -O /src/nginx/3.patch && \
    echo "01bf75b130b8f91075ec913a400a8debfab6da0ac609711c7d412ddbe59dd898  /src/nginx/3.patch" | sha256sum -c - && \
    git -C /src/nginx apply /src/nginx/3.patch && \
    wget -q https://raw.githubusercontent.com/nginx-modules/ngx_http_tls_dyn_size/refs/heads/master/nginx__dynamic_tls_records_"$DTR_VER"%2B.patch -O /src/nginx/4.patch && \
    echo "0aa9c73e7515dbbd48ecc798f7894412c1a50e96e98aee25847e823059faf821  /src/nginx/4.patch" | sha256sum -c - && \
    git -C /src/nginx apply /src/nginx/4.patch && \
    wget -q https://raw.githubusercontent.com/openresty/openresty/refs/heads/master/patches/nginx/"$RCP_VER"/nginx-"$RCP_VER"-resolver_conf_parsing.patch -O /src/nginx/5.patch && \
    echo "bda9db7d2766b20c9490f1ccd6d2da72fee402ade219efb32fe341851dbdd7c8  /src/nginx/5.patch" | sha256sum -c - && \
    git -C /src/nginx apply /src/nginx/5.patch && \
    wget -q https://raw.githubusercontent.com/zlib-ng/patches/refs/heads/master/nginx/"$ZNP_VER"-zlib-ng.patch -O /src/nginx/6.patch && \
    echo "bcd0f2fb9723fc1f251f94cead8d5160e767f7d4a04365331396a72a9ba54c6b  /src/nginx/6.patch" | sha256sum -c - && \
    git -C /src/nginx apply /src/nginx/6.patch && \
    git -C /src/nginx apply /src/nginx-footer.patch && \
    git -C /src/nginx apply /src/nginx-ip-sni.patch && \
    git -C /src/nginx apply /src/nginx-gso-fix.patch && \
    git -C /src/nginx apply /src/nginx-buffer-log.patch && \
    git -C /src/nginx apply /src/nginx-ech-boringssl-awslc.patch && \
    git -C /src/nginx apply /src/nginx-cert-compression-brotli.patch && \
    \
    git-clone-commit.sh https://github.com/google/ngx_brotli "$NB_VER" /src/ngx_brotli && \
    git -C /src/ngx_brotli apply /src/ngx_brotli.patch && \
    git-clone-commit.sh https://github.com/clyfish/ngx_unbrotli "$NUB_VER" /src/ngx_unbrotli && \
    git -C /src/ngx_unbrotli apply /src/ngx_unbrotli.patch && \
    git-clone-commit.sh https://github.com/tokers/zstd-nginx-module "$ZNM_VER" /src/zstd-nginx-module && \
    wget -q https://patch-diff.githubusercontent.com/raw/tokers/zstd-nginx-module/pull/23.patch -O /src/zstd-nginx-module/1.patch && \
    echo "10d1e564e6b8300e0357b40932ba76c45984b33f545042830b21af37c349fbf8  /src/zstd-nginx-module/1.patch" | sha256sum -c - && \
    wget -q https://patch-diff.githubusercontent.com/raw/tokers/zstd-nginx-module/pull/44.patch -O /src/zstd-nginx-module/2.patch && \
    echo "12527df37f8d8757871cb8dd17d6d82a72d564c6af9d996fc7fb2abec93e4d80  /src/zstd-nginx-module/2.patch" | sha256sum -c - && \
    git -C /src/zstd-nginx-module apply /src/zstd-nginx-module.patch && \
    git -C /src/zstd-nginx-module apply /src/zstd-nginx-module/1.patch && \
    git -C /src/zstd-nginx-module apply /src/zstd-nginx-module/2.patch && \
    git-clone-commit.sh https://github.com/HanadaLee/ngx_http_unzstd_filter_module "$NHUZFM_VER" /src/ngx_http_unzstd_filter_module && \
    git-clone-commit.sh https://github.com/aperezdc/ngx-fancyindex "$NF_VER" /src/ngx-fancyindex && \
    wget -q https://patch-diff.githubusercontent.com/raw/aperezdc/ngx-fancyindex/pull/176.patch -O /src/ngx-fancyindex/1.patch && \
    echo "0b76992c0981e5beda1f158493d0334dcbdfe381348ea0eeeb09123bd9aaa4d3  /src/ngx-fancyindex/1.patch" | sha256sum -c - && \
    git -C /src/ngx-fancyindex apply /src/ngx-fancyindex/1.patch && \
    git-clone-commit.sh https://github.com/openresty/headers-more-nginx-module "$HMNM_VER" /src/headers-more-nginx-module && \
    git-clone-commit.sh https://github.com/vision5/ngx_devel_kit "$NDK_VER" /src/ngx_devel_kit && \
    git-clone-commit.sh https://github.com/openresty/lua-nginx-module "$LNM_VER" /src/lua-nginx-module && \
    git -C /src/lua-nginx-module apply /src/lua-nginx-module.patch && \
    \
    git-clone-commit.sh https://github.com/nginx/njs "$NJS_VER" /src/njs && \
    git-clone-commit.sh https://github.com/kvspb/nginx-auth-ldap "$NAL_VER" /src/nginx-auth-ldap && \
    git-clone-commit.sh https://github.com/vozlt/nginx-module-vts "$VTS_VER" /src/nginx-module-vts && \
    git-clone-commit.sh https://github.com/gabihodoroaga/nginx-ntlm-module "$NNTLM_VER" /src/nginx-ntlm-module && \
    git-clone-commit.sh https://github.com/leev/ngx_http_geoip2_module "$NHG2M_VER" /src/ngx_http_geoip2_module

WORKDIR /src/nginx
RUN /src/nginx/auto/configure \
    --build=NPMplus \
    --user=root \
    --group=root \
    --with-debug \
    --with-compat \
    --with-threads \
    --with-file-aio \
    --with-libatomic \
    --with-pcre \
    --with-pcre-jit \
    --without-select_module \
    --without-poll_module \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-stream_realip_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-http_ssl_module \
    --with-http_realip_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_sub_module \
    --with-http_addition_module \
    --with-http_stub_status_module \
    --with-http_auth_request_module \
    --add-module=/src/ngx_brotli \
    --add-module=/src/ngx_unbrotli \
    --add-module=/src/zstd-nginx-module \
    --add-module=/src/ngx_http_unzstd_filter_module \
    --add-module=/src/ngx-fancyindex \
    --add-module=/src/headers-more-nginx-module \
    --add-module=/src/ngx_devel_kit \
    --add-module=/src/lua-nginx-module \
    --add-dynamic-module=/src/njs/nginx \
    --add-dynamic-module=/src/nginx-auth-ldap \
    --add-dynamic-module=/src/nginx-module-vts \
    --add-dynamic-module=/src/nginx-ntlm-module \
    --add-dynamic-module=/src/ngx_http_geoip2_module \
    --with-ld-opt="$LDFLAGS" && \
    \
    make -j "$(nproc)" install

# NginxionS: the attachment is built from openappsec/attachment of NginxionS (build context "attachment"), not
# downloaded at OASA_VER; the changes of attachment.patch of NPMplus are in that code
COPY --from=attachment . /src/attachment
WORKDIR /src/attachment
RUN cmake /src/attachment -G Ninja && \
    ninja && \
    mv -v /src/attachment/attachments/nginx/ngx_module/libngx_module.so /usr/local/nginx/modules/libngx_module.so

# NginxionS: cjson of LuaJIT for the CrowdSec bouncer, built here: the package lua5.1-cjson of Alpine brings Lua 5.1 and
# its CVEs into the image (Grype), and nginx runs LuaJIT
ARG LCJ_VER=5f53e878d0441e1555f53060178c61d161079e06 # 2.1.0.20
RUN git-clone-commit.sh https://github.com/openresty/lua-cjson "$LCJ_VER" /src/lua-cjson && \
    make -C /src/lua-cjson LUA_INCLUDE_DIR="$LUAJIT_INC" CC=clang && \
    llvm-strip -s /src/lua-cjson/cjson.so && \
    file /src/lua-cjson/cjson.so

RUN find /usr/local/nginx/modules -name "*.so" -exec llvm-strip -s {} \; && \
    llvm-strip -s /usr/local/nginx/sbin/nginx && \
    llvm-strip -s /usr/local/lib/libcrypto.so && \
    llvm-strip -s /usr/local/lib/libssl.so && \
    llvm-strip -s /usr/local/bin/bssl && \
    llvm-strip -s /src/attachment/core/shmem_ipc_2/libshmem_ipc_2.so && \
    llvm-strip -s /src/attachment/core/compression/libosrc_compression_utils.so && \
    llvm-strip -s /src/attachment/attachments/nginx/nginx_attachment_util/libosrc_nginx_attachment_util.so && \
    \
    find /usr/local/nginx/modules -name "*.so" -exec file {} \; && \
    file /usr/local/nginx/sbin/nginx && \
    file /usr/local/lib/libcrypto.so && \
    file /usr/local/lib/libssl.so && \
    file /usr/local/bin/bssl && \
    file /src/attachment/core/shmem_ipc_2/libshmem_ipc_2.so && \
    file /src/attachment/core/compression/libosrc_compression_utils.so && \
    file /src/attachment/attachments/nginx/nginx_attachment_util/libosrc_nginx_attachment_util.so && \
    /usr/local/nginx/sbin/nginx -V


FROM --platform="$BUILDPLATFORM" alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS frontend
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ARG NODE_ENV=production
ARG NODE_OPTIONS=--use-openssl-ca
WORKDIR /app
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml /app/
RUN apk upgrade --no-cache -a && \
    apk add --no-cache nodejs pnpm llvm file && \
    pnpm install --frozen-lockfile && \
    pnpm cache delete && \
    find /app/node_modules -name "*.map" -delete && \
    find /app/node_modules -name "*.node" -type f -exec llvm-strip -s {} \; && \
    find /app/node_modules -name "*.node" -type f -exec file {} \;
COPY frontend /app
RUN pnpm formatjs compile-folder src/locale/src src/locale/lang && \
    pnpm tsc && \
    pnpm vite build

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS backend
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ARG NODE_ENV=production
ARG NODE_OPTIONS=--use-openssl-ca
WORKDIR /app
COPY backend/package.json backend/pnpm-lock.yaml backend/pnpm-workspace.yaml /app/
# NginxionS: better-sqlite3 has no prebuilt binary for every Node.js of Alpine (none for 24.22.1/musl): node-gyp,
# a compiler and the headers of Node.js build it from its source then. Only in this stage, not in the image.
RUN apk upgrade --no-cache -a && \
    apk add --no-cache nodejs pnpm llvm file nodejs-dev npm python3 make g++ && \
    ln -s /usr/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js /usr/local/bin/node-gyp && \
    export npm_config_nodedir=/usr && \
    pnpm install --frozen-lockfile --prod && \
    pnpm cache delete && \
    find /app/node_modules -name "*.map" -delete && \
    rm -r /app/node_modules/better-sqlite3/deps/sqlite3 && \
    find /app/node_modules -name "*.node" -type f -exec llvm-strip -s {} \; && \
    find /app/node_modules -name "*.node" -type f -exec file {} \;
COPY backend /app


# NginxionS: lego, the second ACME client (nginxions/backend/nginxions/acme/lego.js): ES256 account keys and the name in the CN of
# the CSR, which some CAs require and certbot does not do. Built from the source of its release (Go module proxy).
# NginxionS: lego is built with the Go of the golang image (the same as deploy/openappsec/Dockerfile, raised by
# Renovate): the go package of Alpine lags behind the fixes of its standard library (Trivy, Grype: GO-2026-6859)
FROM --platform="$BUILDPLATFORM" docker.io/library/golang:1.27-alpine@sha256:eb61c3873c97416fff0116553fff65d67a3549f72e11d9758849a689cdd8b523 AS lego
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ARG TARGETARCH
ARG LEGO_VERSION=v4.35.2
# libraries raised over the ones of the release: their versions have known vulnerabilities (Trivy, docs/DEVSECOPS.md)
ARG LEGO_UPGRADES="golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2 golang.org/x/net@v0.62.0 golang.org/x/text@v0.43.0 google.golang.org/grpc@v1.85.0 github.com/go-jose/go-jose/v4@v4.1.9 software.sslmate.com/src/go-pkcs12@v0.7.2"
WORKDIR /build
RUN apk add --no-cache file && \
    export GOTOOLCHAIN=local GOFLAGS=-trimpath GOPATH=/go && \
    go mod init build && \
    go get "github.com/go-acme/lego/v4/cmd/lego@$LEGO_VERSION" $LEGO_UPGRADES && \
    CGO_ENABLED=0 GOOS=linux GOARCH="$TARGETARCH" \
      go build -ldflags "-s -w -X main.version=$LEGO_VERSION" -o /lego github.com/go-acme/lego/v4/cmd/lego && \
    rm -rf /go /root/.cache && \
    { /lego --version 2>/dev/null || file /lego; }

# NginxionS: offline CrowdSec seed (hub snapshot) for the official crowdsec image, see nginxions/crowdsec-seed/seed.sh
FROM docker.io/crowdsecurity/crowdsec:${CROWDSEC_VERSION} AS crowdsec-seed
ARG HUB_BRANCH=master
ARG HUB_ITEMS="parsers crowdsecurity/docker-logs crowdsecurity/cri-logs; collections ZoeyVid/npmplus crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules"
ARG HUB_URL_TEMPLATE=
COPY crowdsec-seed/seed.sh /seed.sh
RUN --mount=type=secret,id=ca_bundle,required=false sh /seed.sh

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ENV NODE_ENV=production
ENV NODE_OPTIONS=--use-openssl-ca
ARG LRC_VER=6fec23e2149c88b33b39fec8a5ebdd67a3e0dd88 # v0.1.34rc3
ARG LRL_VER=3ff6300e68b73ba20e909c7d16bd839aef2e5a4b # v0.15
ARG LCSB_VER=3e82dd61508ed9683b5007f823c69b112c59ac6f # v1.0.14
# NginxionS: lua-resty-string from git like the other Lua libraries: its rock has no source package on luarocks.org,
# luarocks fetched the archive of GitHub (archive/v0.09.tar.gz), which fails again and again, and the build with it
ARG LRS_VER=e363ac306db6135bdda9399511742fe36ebd4cbb # v0.09
# NginxionS: lua-resty-http and lua-resty-openssl from git too, not with luarocks: luarocks needs Lua 5.1 (its CVEs, Grype)
ARG LRH_VER=03995ff9a08194d48d446ed2fa099cd6de38fbef # v0.18.0
ARG LRO_VER=4ebee84ec3d829ef610005db1978ae591ed77a31 # 1.9.0

COPY --from=nginx /usr/local/nginx                                                                         /usr/local/nginx
COPY --from=nginx /usr/local/bin/bssl                                                                      /usr/local/bin/bssl
# NginxionS: lego, see the stage above
COPY --from=lego  /lego                                                                                    /usr/local/bin/lego
COPY --from=nginx /usr/local/lib/libssl.so                                                                 /usr/local/lib/libssl.so
COPY --from=nginx /usr/local/lib/libcrypto.so                                                              /usr/local/lib/libcrypto.so
# NginxionS: cjson of LuaJIT, see the stage nginx
COPY --from=nginx /src/lua-cjson/cjson.so                                                                  /usr/lib/lua/5.1/cjson.so
COPY --from=nginx /src/attachment/core/shmem_ipc_2/libshmem_ipc_2.so                                       /usr/local/lib/libshmem_ipc_2.so
COPY --from=nginx /src/attachment/core/compression/libosrc_compression_utils.so                            /usr/local/lib/libosrc_compression_utils.so
COPY --from=nginx /src/attachment/attachments/nginx/nginx_attachment_util/libosrc_nginx_attachment_util.so /usr/local/lib/libosrc_nginx_attachment_util.so

COPY --from=backend  /app      /app

COPY rootfs  /
COPY LICENSE.MIT /LICENSE.MIT
COPY COPYING /COPYING

WORKDIR /app
RUN apk upgrade --no-cache -a && \
    apk add --no-cache tzdata tini llvm-libunwind libc++ \
                       pcre2 luajit zlib-ng brotli zstd libxml2 libldap quickjs-ng-libs libmaxminddb-libs \
                       curl coreutils findutils grep jq openssl shadow su-exec util-linux-misc \
                       bash bash-completion nano \
                       logrotate goaccess fcgi \
                       git make \
                       nodejs python3 && \
    \
    git config --global advice.detachedHead false && \
    git config --global init.defaultBranch main && \
    \
    mkdir -p /usr/local/share/lua/5.1/resty && \
    git-clone-commit.sh https://github.com/ledgetech/lua-resty-http "$LRH_VER" /src/lua-resty-http && \
    cp -r /src/lua-resty-http/lib/resty/. /usr/local/share/lua/5.1/resty/ && \
    git-clone-commit.sh https://github.com/fffonion/lua-resty-openssl "$LRO_VER" /src/lua-resty-openssl && \
    cp -r /src/lua-resty-openssl/lib/resty/. /usr/local/share/lua/5.1/resty/ && \
    sed -i 's|^local legacy_nids = {}$|C.ERR_clear_error()\n&|' /usr/local/share/lua/5.1/resty/openssl/pkey.lua && \
    \
    git-clone-commit.sh https://github.com/openresty/lua-resty-core "$LRC_VER" /src/lua-resty-core && \
    make -C /src/lua-resty-core -j "$(nproc)" install LUA_LIB_DIR=/usr/local/share/lua/5.1 && \
    \
    git-clone-commit.sh https://github.com/openresty/lua-resty-lrucache "$LRL_VER" /src/lua-resty-lrucache && \
    make -C /src/lua-resty-lrucache -j "$(nproc)" install LUA_LIB_DIR=/usr/local/share/lua/5.1 && \
    \
    git-clone-commit.sh https://github.com/openresty/lua-resty-string "$LRS_VER" /src/lua-resty-string && \
    make -C /src/lua-resty-string install LUA_LIB_DIR=/usr/local/share/lua/5.1 && \
    \
    git-clone-commit.sh https://github.com/crowdsecurity/lua-cs-bouncer "$LCSB_VER" /src/lua-cs-bouncer && \
    mv /src/lua-cs-bouncer/lib/* /usr/local/share/lua/5.1 && \
    mv /src/lua-cs-bouncer/templates/captcha.html /etc/captcha.html.original && \
    mv /src/lua-cs-bouncer/templates/ban.html /etc/ban.html.original && \
    \
    rm -r /src && \
    apk del --no-cache git make && \
# NginxionS: wall (util-linux-misc) is setgid tty to write to the terminals of users; a container has none (Dockle)
    chmod g-s /usr/bin/wall && \
# NginxionS: no setuid program: passwd and the like are for users who log in, the services run as their own users
    find / -xdev -perm /6000 -type f -exec chmod ug-s {} + && \
    \
    sed -i "s|placeholder|$(cat /app/package.json | jq -r .version)|g" /usr/local/nginx/conf/conf.d/crowdsec.conf.disabled && \
    \
    python3 -m venv /usr/local && \
# NginxionS: setuptools too: the one of the venv has known vulnerabilities (Trivy, docs/DEVSECOPS.md); pinned versions
# (hadolint DL3013), raised with the image
    pip install --no-cache-dir --upgrade pip==26.3 setuptools==84.2.1 certbot==5.10.0 && \
    \
    wget -q https://raw.githubusercontent.com/tomwassenberg/certbot-ocsp-fetcher/refs/heads/main/certbot-ocsp-fetcher -O - | sed "s|/live||g" > /usr/local/bin/certbot-ocsp-fetcher.sh && \
    wget -q https://raw.githubusercontent.com/vasilevich/nginxbeautifier/5cee8db2a505f2a253e24691399c828c043071fc/index.js -O /usr/local/bin/nginxbeautifier && \
    wget -q https://raw.githubusercontent.com/vasilevich/nginxbeautifier/5cee8db2a505f2a253e24691399c828c043071fc/nginxbeautifier.js -O /usr/local/bin/nginxbeautifier.js && \
    \
    ln -s /usr/local/nginx/sbin/nginx /usr/local/bin/nginx && \
    ln -s /app/password-reset.js /usr/local/bin/password-reset.js && \
    ln -s /app/sqlite-vaccum.js /usr/local/bin/sqlite-vaccum.js && \
    ln -s /app/index.js /usr/local/bin/index.js && \
    \
    chmod +x /usr/local/bin/*

COPY --from=frontend /app/dist /app/frontend
# NginxionS: offline CrowdSec seed, copied into the crowdsec volumes by nginxions-init
COPY --from=crowdsec-seed /seed /opt/nginxions/crowdsec-seed

ENTRYPOINT ["tini", "--", "entrypoint.sh"]
# NginxionS: exec form (hadolint DL3025), no shell around the check
HEALTHCHECK CMD ["healthcheck.sh"]

LABEL com.centurylinklabs.watchtower.monitor-only="true"
LABEL wud.watch="false"
LABEL wud.watch.digest="false"
