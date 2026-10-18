#!/usr/bin/env bash
# release.sh — cut a GitHub release of the storm warmer.
#
# Usage:
#   ./release.sh <version> [--dry-run]
#
# <version> is the bare version number, e.g. 0.2.0 (the tag becomes v0.2.0).
# What it does:
#   1. Writes <version> into the version const in esi.go and commits it.
#   2. Builds storm-amd64 and storm-arm64 with the exact commands CI uses
#      (go build -trimpath), so the digests match a CI build of the same tag.
#   3. Tags v<version>, pushes the commit and the tag.
#   4. Creates the GitHub release with four assets: the two bare binaries
#      (storm-amd64, storm-arm64) and the two tarballs CI produces
#      (storm-linux-<arch>.tar.gz, binary + setup.sh).
#   5. Prints the SHA-256 of each BARE binary — those are the digests to add
#      to the EveSynapse release library (type: Storm) so the admin Build
#      column can name this build. The node's build claim is the hash of
#      its own executable, so it is the bare binary's digest that matters,
#      not the tarball's.
#
# --dry-run does steps 1-2 locally (build + digests) and stops: no commit,
# no tag, no push, no release. The esi.go edit is left in the working tree.
#
# Requirements: go, git, and an authenticated gh (gh auth status) on the
# machine running this. Deploying to the storm box is NOT part of this
# script: grab the release asset there and follow the usual
# download -> install -> restart.
set -euo pipefail

VERSION="${1:-}"
DRY_RUN=0
[ "${2:-}" = "--dry-run" ] && DRY_RUN=1
if [ -z "$VERSION" ]; then
  echo "usage: ./release.sh <version> [--dry-run]" >&2
  exit 1
fi
TAG="v$VERSION"

cd "$(dirname "$0")"

# Preflight.
command -v go >/dev/null || { echo "go not found" >&2; exit 1; }
command -v gh >/dev/null || { echo "gh not found" >&2; exit 1; }
if [ "$DRY_RUN" -eq 0 ]; then
  gh auth status >/dev/null 2>&1 || { echo "gh is not authenticated" >&2; exit 1; }
  if [ -n "$(git status --porcelain)" ]; then
    echo "working tree is dirty; commit or stash first" >&2
    exit 1
  fi
  if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "tag $TAG already exists" >&2
    exit 1
  fi
fi

# 1. Version const.
sed -i.bak -E "s/^const version = \".*\"/const version = \"$VERSION\"/" esi.go
rm -f esi.go.bak
grep -q "const version = \"$VERSION\"" esi.go || { echo "could not set version in esi.go" >&2; exit 1; }
echo "version const -> $VERSION"

# 2. Builds (identical to .github/workflows/build.yaml).
export CGO_ENABLED=0
GOOS=linux GOARCH=amd64 go build -trimpath -o storm-amd64 .
GOOS=linux GOARCH=arm64 go build -trimpath -o storm-arm64 .
tar -czf storm-linux-amd64.tar.gz storm-amd64 setup.sh
tar -czf storm-linux-arm64.tar.gz storm-arm64 setup.sh
echo "built storm-amd64, storm-arm64 + tarballs"

if [ "$DRY_RUN" -eq 1 ]; then
  echo
  echo "DRY RUN — bare binary SHA-256 (release-library digests, type: Storm, label: Storm $TAG):"
  sha256sum storm-amd64 storm-arm64
  echo
  echo "Skipped: commit, tag, push, GitHub release. esi.go edit left in the working tree."
  exit 0
fi

# 3. Commit + tag + push.
git add esi.go
git commit -q -m "Release $TAG"
git tag -a "$TAG" -m "Storm $TAG"
git push -q origin main
git push -q origin "$TAG"
echo "pushed main + tag $TAG"

# 4. GitHub release with the bare binaries AND the tarballs.
gh release create "$TAG" \
  storm-amd64 storm-arm64 \
  storm-linux-amd64.tar.gz storm-linux-arm64.tar.gz \
  --title "Storm $TAG" \
  --notes "Storm warmer $TAG. Bare binaries (storm-amd64, storm-arm64) and per-arch tarballs with setup.sh."
echo "release $TAG created"

# 5. The library lines.
echo
echo "Add these digests to the EveSynapse release library (type: Storm, label: Storm $TAG):"
sha256sum storm-amd64 storm-arm64
