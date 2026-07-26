#!/usr/bin/env bash

set -euo pipefail

mode="${1:-full}"
case "${mode}" in
  fast|full) ;;
  *) echo "usage: $0 fast|full" >&2; exit 2 ;;
esac

fail() {
  echo "::error::repository policy (${mode}) failed: $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing required file: $1"
}

require_text() {
  local pattern="$1"
  local path="$2"
  rg -q --fixed-strings -- "${pattern}" "${path}" || fail "missing contract '${pattern}' in ${path}"
}

for path in \
  AGENT.md AGENTS.md CLAUDE.md CONTRIBUTING.md README.md ROADMAP.md TODO.md CHANGELOG.md \
  LICENSE Cargo.toml Cargo.lock docs/ci-cd-policy.md docs/manual-intervention.md \
  .github/copilot-instructions.md .github/scripts/detect-ci-changes.sh \
  .github/workflows/ci.yml .github/workflows/release.yml; do
  require_file "${path}"
done

tracked_paths="$(git ls-files)"
if rg -n '(^|/)(target|dist|node_modules|coverage|\.next|\.turbo|\.gradle|DerivedData)(/|$)' <<<"${tracked_paths}"; then
  fail "tracked build output is forbidden"
fi
if rg -n -i '(^|/)(id_(rsa|dsa|ecdsa|ed25519)|\.env($|\.)|[^/]+\.(p12|pfx|jks|keystore|mobileprovision|provisionprofile|key|pem))$' <<<"${tracked_paths}"; then
  fail "tracked credential or signing material is forbidden"
fi
if git grep -nEI '(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|AIza[0-9A-Za-z_-]{35})' -- ':!*.md' ':!.github/workflows/ci.yml'; then
  fail "obvious credential pattern found in tracked source"
fi

declare -a fast_contracts=(
  $'^name: CI\t.github/workflows/ci.yml'
  $'^  changes:\t.github/workflows/ci.yml'
  $'^  policy-fast:\t.github/workflows/ci.yml'
  $'^  policy-full:\t.github/workflows/ci.yml'
  $'^  ci-summary:\t.github/workflows/ci.yml'
  $'^name: Release\t.github/workflows/release.yml'
  $'^  release-ci-gate:\t.github/workflows/release.yml'
  $'^  publish-eligibility-gate:\t.github/workflows/release.yml'
  $'当前阶段进入 P4 Client And Platform Integration\tREADME.md'
  $'当前阶段：P4 Client And Platform Integration\tROADMAP.md'
  $'当前阶段是 P4 Client And Platform Integration\tTODO.md'
  $'linux-artifact-release-state=confirmed-release-path\tdocs/manual-intervention.md'
)

for contract in "${fast_contracts[@]}"; do
  pattern="${contract%%$'\t'*}"
  path="${contract#*$'\t'}"
  rg -q --pcre2 "${pattern}" "${path}" || fail "missing fast contract '${pattern}' in ${path}"
done

if [[ "${mode}" == fast ]]; then
  echo "Repository policy fast checks passed."
  exit 0
fi

declare -a full_contracts=(
  $'persistent-subscription-catalog-source-contract=active\tdocs/architecture/subscription-catalog-persistence-source-contract.md'
  $'persistent-subscription-catalog-operation=add\tdocs/architecture/subscription-catalog-persistence-source-contract.md'
  $'persistent-subscription-catalog-update-operation=update\tdocs/architecture/subscription-catalog-persistence-source-contract.md'
  $'persistent-subscription-catalog-rollback-operation=rollback\tdocs/architecture/subscription-catalog-persistence-source-contract.md'
  $'CommandSubscriptionCatalogStore\tdocs/architecture/subscription-catalog-persistence-source-contract.md'
  $'Managed Foreground Session Status Source Contract\tdocs/architecture/managed-foreground-session-status-source-contract.md'
  $'Managed Foreground Session Event Source Contract\tdocs/architecture/managed-foreground-session-event-source-contract.md'
  $'Managed Foreground Session Log Source Contract\tdocs/architecture/managed-foreground-session-log-source-contract.md'
  $'Loopback Selector Switch\tdocs/architecture/linux-native-proxy-engine-start.md'
  $'MITM_CLI_COMMAND_GATE\tREADME.md'
  $'MITM_CERTIFICATE_LIFECYCLE_GATE\tREADME.md'
  $'MITM_BROWSER_CAPTURE_GATE\tREADME.md'
  $'MITM_HTTP_TLS_DATA_PLANE_GATE\tREADME.md'
  $'third-party-plugin-onboarding-status=active\tdocs/architecture/third-party-plugin-onboarding-process.md'
  $'linux-artifact-license-notice-status=confirmed\tdocs/manual-intervention.md'
)

for contract in "${full_contracts[@]}"; do
  pattern="${contract%%$'\t'*}"
  path="${contract#*$'\t'}"
  require_text "${pattern}" "${path}"
done

echo "Repository policy ${mode} checks passed."
