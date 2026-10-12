#!/usr/bin/env bash
# Static gate for apps/ios/Package.swift, run only in GitHub Actions on macos-26.
# Contracts: docs/architecture/ios-package-swift-source-ownership-activation-preflight-contract.md
#            docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md
#            docs/architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md
#
# Usage: verify-ios-package-manifest.sh <manifest-only|source>
#   manifest-only: Package.swift may exist, Swift source must still be absent.
#   source:        Swift source gate passed; every target path must contain Swift files.
# This script never runs swift build or swift test; those belong to the swift-build-test job.
set -euo pipefail

phase="${1:-}"
case "${phase}" in
  manifest-only | source) ;;
  *)
    echo "::error::usage: verify-ios-package-manifest.sh <manifest-only|source>"
    exit 2
    ;;
esac

manifest="apps/ios/Package.swift"

fail() {
  echo "::error::$*"
  exit 1
}

test -f "${manifest}" || fail "missing ${manifest}"

stray="$(find . -path ./.git -prune -o -name Package.swift -print | grep -v -x "./${manifest}" || true)"
if [[ -n "${stray}" ]]; then
  fail "Package.swift must exist only at ${manifest}: ${stray}"
fi

# Product and target names fixed by the manifest-only contract.
grep -q 'name: "NetworkCoreIOS"' "${manifest}" || fail "product NetworkCoreIOS is missing"
for target in NetworkCoreBridge NetworkCoreApp NetworkCoreBridgeTests; do
  grep -q "name: \"${target}\"" "${manifest}" || fail "target ${target} is missing"
done

# The Network Extension target stays blocked until the Xcode/Network Extension gate.
if grep -Eq 'name: "NetworkCorePacketTunnel"|executableTarget|NetworkExtension' "${manifest}"; then
  fail "NetworkCorePacketTunnel target must not be declared before the Network Extension gate"
fi

# No secrets, signing settings, local paths, generated output or remote dependencies.
forbidden='\.\./|/Users/|/private/|/var/folders/|DerivedData|DEVELOPMENT_TEAM|PRODUCT_BUNDLE_IDENTIFIER|CODE_SIGN|[Pp]rovision|[Cc]ertificate|App Store Connect|\.package\(|[A-Z0-9]{10}'
if grep -Eq "${forbidden}" "${manifest}"; then
  fail "Package.swift contains forbidden signing, path, identifier or dependency material"
fi

# Every target path must stay under Sources/ or Tests/ inside apps/ios.
paths="$(grep -o 'path: "[^"]*"' "${manifest}" | sed -E 's/^path: "(.*)"$/\1/' || true)"
while IFS= read -r p; do
  [[ -z "${p}" ]] && continue
  case "${p}" in
    Sources/* | Tests/*) ;;
    *) fail "target path must stay under Sources or Tests: ${p}" ;;
  esac
done <<< "${paths}"

if [[ "${phase}" == "manifest-only" ]]; then
  if find apps/ios/Sources apps/ios/Tests -name '*.swift' -print 2>/dev/null | grep -q .; then
    fail "Swift source must not exist before the Swift source gate"
  fi
  echo "ios package manifest-only validation passed; swift build and swift test stay blocked"
  exit 0
fi

while IFS= read -r p; do
  [[ -z "${p}" ]] && continue
  if ! find "apps/ios/${p}" -name '*.swift' -print 2>/dev/null | grep -q .; then
    fail "target path apps/ios/${p} has no Swift source"
  fi
done <<< "${paths}"
echo "ios package source validation passed"
