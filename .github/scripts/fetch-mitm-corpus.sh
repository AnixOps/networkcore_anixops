#!/usr/bin/env bash
# Downloads the public plugin corpus pinned in
# crates/mitm-policy/tests/fixtures/public-corpus/manifest.tsv into $1 and
# checks every file's SHA-256. The files are third-party content and are never
# committed.
set -euo pipefail

out="${1:?usage: fetch-mitm-corpus.sh <directory>}"
manifest="crates/mitm-policy/tests/fixtures/public-corpus/manifest.tsv"
mkdir -p "$out"

failed=0
while IFS=$'\t' read -r id dialect repo commit path sha256; do
  case "$id" in ''|'#'*) continue ;; esac
  url="https://raw.githubusercontent.com/${repo}/${commit}/${path}"
  if ! curl -fsSL --retry 3 --retry-delay 2 --max-time 60 -o "$out/$id" "$url"; then
    echo "::error::${id}: download failed (${url})"
    failed=1
    continue
  fi
  actual="$(sha256sum "$out/$id" | cut -d' ' -f1)"
  if [ "$actual" != "$sha256" ]; then
    echo "::error::${id}: sha256 ${actual} does not match the manifest (${sha256})"
    failed=1
  fi
done < "$manifest"
exit "$failed"
