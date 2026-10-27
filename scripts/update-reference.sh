#!/usr/bin/env bash
# Refreshes reference/ snapshots from upstream and records their commits in reference/VERSIONS.md.
# reference/ is read-only source material: it is never built, linted or shipped.
# Usage: scripts/update-reference.sh [name...]   (default: all)
set -euo pipefail

cd "$(dirname "$0")/.."

declare -A REPOS=(
  [open-appsec-npm]="https://github.com/openappsec/open-appsec-npm"
  [openappsec]="https://github.com/openappsec/openappsec"
  [smartsync]="https://github.com/openappsec/smartsync"
  [smartsync-tuning]="https://github.com/openappsec/smartsync-tuning"
  [smartsync-shared-files]="https://github.com/openappsec/smartsync-shared-files"
)

names=("$@")
[ ${#names[@]} -eq 0 ] && names=(open-appsec-npm openappsec smartsync smartsync-tuning smartsync-shared-files)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

versions=reference/VERSIONS.md
[ -f "$versions" ] || printf '# reference/ versions\n\n| Name | Upstream | Commit | Commit date |\n|---|---|---|---|\n' > "$versions"

for name in "${names[@]}"; do
  url=${REPOS[$name]:?unknown reference: $name}
  git clone -q --depth 1 "$url" "$tmp/$name"
  sha=$(git -C "$tmp/$name" rev-parse HEAD)
  date=$(git -C "$tmp/$name" log -1 --format=%cs)
  rm -rf "$tmp/$name/.git" "reference/$name"
  mv "$tmp/$name" "reference/$name"
  row="| $name | $url | \`$sha\` | $date |"
  if grep -q "^| $name |" "$versions"; then
    sed -i "s#^| $name |.*#$row#" "$versions"
  else
    echo "$row" >> "$versions"
  fi
  echo "$name -> ${sha:0:7} ($date)"
done
