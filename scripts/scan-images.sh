#!/usr/bin/env bash
# Images of NPMOS as they are published: vulnerabilities of their packages and secrets left in their layers
# (Trivy), their SBOM (Syft: CycloneDX and SPDX) and a second opinion on it (Grype), and the CIS checks of a
# container image (Dockle). The images must be local (built or pulled).
#
#   NPMOS_REGISTRY=docker.io/opensophy NPMOS_VERSION=<tag> scripts/scan-images.sh
#
# Writes the reports to $OUT (reports/images). Exits non-zero only when a tool fails: what fails the run is decided by
# scripts/security-report.mjs.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=../.github/security/tools.env
. .github/security/tools.env

: "${NPMOS_REGISTRY:?}" "${NPMOS_VERSION:?}"
OUT="${OUT:-reports/images}"
mkdir -p "$OUT"
out="$(cd "$OUT" && pwd)"
sock=(-v /var/run/docker.sock:/var/run/docker.sock)
# the vulnerability database of Trivy is downloaded once for all the images
cache=(-v npmos-trivy-cache:/root/.cache/)

for img in npmos npmos-openappsec; do
  ref="$NPMOS_REGISTRY/$img:$NPMOS_VERSION"
  echo "==> $img: vulnerabilities and secrets (Trivy)"
  docker run --rm "${sock[@]}" "${cache[@]}" -v "$out:/out" "$TRIVY_IMAGE" image --quiet --scanners vuln,secret \
    --format json --output "/out/trivy-$img.json" "$ref"
  docker run --rm "${cache[@]}" -v "$out:/out" "$TRIVY_IMAGE" convert --format sarif \
    --output "/out/trivy-$img.sarif" "/out/trivy-$img.json"

  echo "==> $img: SBOM (Syft)"
  docker run --rm "${sock[@]}" -v "$out:/out" "$SYFT_IMAGE" scan "docker:$ref" -q --source-name "$img" \
    --source-version "$NPMOS_VERSION" -o "cyclonedx-json=/out/sbom-$img.cdx.json" -o "spdx-json=/out/sbom-$img.spdx.json"

  echo "==> $img: vulnerabilities of the SBOM (Grype)"
  docker run --rm -v "$out:/out" "$GRYPE_IMAGE" "sbom:/out/sbom-$img.cdx.json" -q -o json --file "/out/grype-$img.json"

  echo "==> $img: CIS checks of the image (Dockle)"
  docker run --rm "${sock[@]}" -v "$out:/out" "$DOCKLE_IMAGE" --exit-code 0 -f json -o "/out/dockle-$img.json" "$ref"
done
echo "OK: images scanned, reports in $OUT"
