#!/usr/bin/env bash
# verify-release.sh — verify a published @chio/bridge release.
#
# Usage:
#   scripts/verify-release.sh <version>
#   CHIO_DRY_RUN=true scripts/verify-release.sh <version> [<fixture.tgz>]
#
# Checks:
#   - npm registry signature (npm audit signatures)
#   - SLSA L3 provenance (slsa-verifier verify-npm-package)
#   - tarball sha256 against npm-published metadata
#
# Required tools:
#   npm >= 9.5, slsa-verifier
#
# Dry-run mode (CHIO_DRY_RUN=true) skips network calls; useful for syntax
# checking and CI shimming. Pass a fixture .tgz as $2 to short-circuit
# the npm pack step.

set -euo pipefail

PKG="@chio/bridge"
SOURCE_REPO="${CHIO_GH_OWNER:-owner}/chio-bridge"
HERE="$(cd "$(dirname "$0")" && pwd)"

# Locate the shared library.
LIB=""
for candidate in \
  "$HERE/verify-release-lib.sh" \
  "$HERE/../../chio-ci-actions/scripts/verify-release-lib.sh" \
  "/usr/local/lib/chio/verify-release-lib.sh"; do
  if [[ -f "$candidate" ]]; then LIB="$candidate"; break; fi
done
if [[ -z "$LIB" ]]; then
  echo "ERROR: chio-ci-actions/scripts/verify-release-lib.sh not found" >&2
  exit 2
fi
# shellcheck disable=SC1090
source "$LIB"

VERSION="${1:-}"
FIXTURE="${2:-}"

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version> [<fixture.tgz>]" >&2
  exit 1
fi

echo "=== Verifying $PKG@$VERSION (source: github.com/$SOURCE_REPO) ==="

failed=0

if [[ "$CHIO_DRY_RUN" != "true" ]]; then
  chio::require_tools npm slsa-verifier shasum
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [[ -n "$FIXTURE" && -f "$FIXTURE" ]]; then
  echo "Using fixture: $FIXTURE"
  cp "$FIXTURE" "$tmp/"
  tarball="$(basename "$FIXTURE")"
elif [[ "$CHIO_DRY_RUN" == "true" ]]; then
  echo "[DRY] would: npm pack $PKG@$VERSION"
  tarball="chio-bridge-${VERSION#v}.tgz"
  : > "$tmp/$tarball"
else
  tarball="$(chio::download_npm "$PKG" "$VERSION" "$tmp")"
fi

chio::verify_npm_provenance "$PKG" "$VERSION" || failed=$((failed+1))
chio::verify_slsa_npm "$tmp/$tarball" "$PKG" "$SOURCE_REPO" || failed=$((failed+1))

chio::summary "$PKG@$VERSION" "$failed"
