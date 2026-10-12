#!/usr/bin/env bash
# Prints the iOS activation placeholder fields that the release workflow must output.
# Each contract owns exactly one ```text block whose lines are key=value fields; the
# contracts are the single source of truth so the release output cannot drift from them.
set -euo pipefail

contracts=(
  docs/architecture/ios-package-swift-source-ownership-activation-preflight-contract.md
  docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md
  docs/architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md
)

for contract in "${contracts[@]}"; do
  test -f "${contract}" || {
    echo "::error::missing iOS activation contract ${contract}"
    exit 1
  }
  awk '
    /^```text$/ { inblock = 1; buf = ""; next }
    /^```$/ && inblock {
      if (buf ~ /contract=present/) printf "%s", buf
      inblock = 0
      next
    }
    inblock { buf = buf $0 "\n" }
  ' "${contract}"
done
