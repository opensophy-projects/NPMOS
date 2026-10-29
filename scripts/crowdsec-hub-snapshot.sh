#!/usr/bin/env bash
# Makes a CrowdSec hub snapshot for nodes without internet: run it on a machine with internet and
# Docker, then upload the archive in NPMOS (CrowdSec → Hub → Upload snapshot).
#
#   scripts/crowdsec-hub-snapshot.sh                         # crowdsec-hub-snapshot.tar.gz
#   scripts/crowdsec-hub-snapshot.sh hub.tar.gz "collections crowdsecurity/nextcloud; parsers a/b"
#
# The archive holds .index.json (the whole hub with content, as `cscli hub update --with-content`
# makes it) and data/ (data files of the items given, installed in a throwaway container: GeoIP
# databases, word lists). Items not given install from the snapshot too, but those that need data
# files then need a snapshot with them. Default items: the base set of the NPMOS image.
set -euo pipefail

cd "$(dirname "$0")/.."
CROWDSEC_VERSION=$(sed -n 's/^CROWDSEC_VERSION=//p' deploy/.env)
out="${1:-crowdsec-hub-snapshot.tar.gz}"
items="${2:-parsers crowdsecurity/docker-logs crowdsecurity/cri-logs openappsec/openappsec-logs crowdsecurity/whitelists; collections ZoeyVid/npmplus crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

docker run --rm -e ITEMS="$items" -v "$work:/out" --entrypoint /bin/sh \
  "docker.io/crowdsecurity/crowdsec:${CROWDSEC_VERSION}" -c '
    set -eu
    cscli hub update --with-content
    echo "$ITEMS" | tr ";" "\n" | while read -r type names; do
      # shellcheck disable=SC2086
      [ -z "$type" ] || cscli "$type" install $names
    done
    mkdir -p /out/data
    cp /etc/crowdsec/hub/.index.json /out/
    find /var/lib/crowdsec/data -maxdepth 1 -type f ! -name "crowdsec.db*" -exec cp -L {} /out/data/ \;
    chmod -R a+rX /out
  '

tar -czf "$out" -C "$work" .index.json data
echo "Hub snapshot: $out ($(du -h "$out" | cut -f1)), upload it in CrowdSec → Hub"
