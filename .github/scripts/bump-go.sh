#!/usr/bin/env bash
# Move the `go` directive in go.mod to the newest stable patch release of the
# same minor line (never across minors), together with every other file that
# pins it. Prints the new version, or nothing if go.mod is already current.
#
# Usage: .github/scripts/bump-go.sh [go-dl-index.json]
#   The index defaults to https://go.dev/dl/?mode=json&include=all.
set -euo pipefail

semver='^[0-9]+\.[0-9]+\.[0-9]+$'

current=$(awk '$1 == "go" { print $2; exit }' go.mod)
[[ $current =~ $semver ]] || { echo "unexpected go directive: '$current'" >&2; exit 1; }
minor=${current%.*}

index=${1:-}
if [[ -z $index ]]; then
  index=$(mktemp)
  trap 'rm -f "$index"' EXIT
  curl -fsSL 'https://go.dev/dl/?mode=json&include=all' -o "$index"
fi

latest=$(jq -r --arg p "go$minor." \
  '.[] | select(.stable) | .version | select(startswith($p)) | ltrimstr("go")' "$index" \
  | sort -V | tail -n1)
[[ $latest =~ $semver ]] || { echo "no stable go$minor.x release in the index" >&2; exit 1; }

# Nothing to do unless latest sorts strictly after current.
if [[ $latest == "$current" ]] || [[ $(printf '%s\n%s\n' "$current" "$latest" | sort -V | tail -n1) != "$latest" ]]; then
  exit 0
fi

export CUR="$current" NEW="$latest"
# Exact version only: 1.26.1 must not match inside 1.26.10.
replace_version() { perl -i -pe 's/(?<![\d.])\Q$ENV{CUR}\E(?![\d])/$ENV{NEW}/g' "$@"; }

replace_version go.mod
[[ -f README.md ]] && replace_version README.md

# setup.sh verifies the downloaded tarball against pinned SHA-256s.
if [[ -f setup.sh ]]; then
  for arch in amd64 arm64; do
    sum=$(jq -r --arg f "go$latest.linux-$arch.tar.gz" \
      '[.[].files[] | select(.filename == $f) | .sha256][0] // empty' "$index")
    [[ $sum =~ ^[0-9a-f]{64}$ ]] || { echo "no sha256 for go$latest.linux-$arch.tar.gz" >&2; exit 1; }
    ARCH=$arch SUM=$sum perl -i -pe \
      's/go\Q$ENV{CUR}\E\.linux-\Q$ENV{ARCH}\E\.tar\.gz\) GO_SHA256="[0-9a-f]{64}"/go$ENV{NEW}.linux-$ENV{ARCH}.tar.gz) GO_SHA256="$ENV{SUM}"/' \
      setup.sh
  done
  replace_version setup.sh
fi

# Anything still naming the old version is a pin this script doesn't know
# about yet. Fail rather than ship a half-bumped tree.
if git grep -nP "(?<![\d.])\Q$current\E(?![\d])" -- . ':!go.sum'; then
  echo "the files above still reference $current; teach bump-go.sh about them" >&2
  exit 1
fi

echo "$latest"
