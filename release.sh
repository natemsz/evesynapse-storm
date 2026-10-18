#!/usr/bin/env bash
# release.sh — start a storm release. The release itself is built,
# attested and published by the Release workflow (.github/workflows/release.yml)
# when the tag lands; this script only does the local part:
#
#   ./release.sh <version>     e.g. ./release.sh 0.2.0
#
#   1. Writes <version> into the version const in esi.go and commits it.
#   2. Creates the annotated tag v<version> (signed if your git config
#      signs tags: tag.gpgsign / user.signingkey).
#   3. Pushes the commit and the tag. The tag push triggers the workflow.
#
# Watch the run in the repo's Actions tab. When it finishes, the release
# carries the bare binaries, tarballs, SHA256SUMS and build-provenance
# attestations; the binaries' SHA-256 digests (also in the release's asset
# list via the API) are what get added to the EveSynapse release library,
# type: Storm.
set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "usage: ./release.sh <version>" >&2
  exit 1
fi
TAG="v$VERSION"
cd "$(dirname "$0")"

if [ -n "$(git status --porcelain)" ]; then
  echo "working tree is dirty; commit or stash first" >&2
  exit 1
fi
if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "tag $TAG already exists" >&2
  exit 1
fi

sed -i.bak -E "s/^const version = \".*\"/const version = \"$VERSION\"/" esi.go
rm -f esi.go.bak
grep -q "const version = \"$VERSION\"" esi.go || { echo "could not set version in esi.go" >&2; exit 1; }

git add esi.go
git commit -q -m "Release $TAG"
git tag -a "$TAG" -m "Storm $TAG"
git push -q origin main
git push -q origin "$TAG"
echo "pushed main + tag $TAG — the Release workflow takes it from here."
