#!/usr/bin/env bash

set -euo pipefail

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

event_name="${EVENT_NAME:-}"
ref_type="${REF_TYPE:-}"
base_sha="${BASE_SHA:-}"
head_sha="${HEAD_SHA:-}"

docs=false
governance=false
go=false
rust=false
node=false
windows=false
linux=false
ios=false
apple=false
workflow=false
release_sensitive=false
full_matrix=false
unknown=false
change_source=diff
changed_file_count=0

mark() {
  printf -v "$1" '%s' true
}

mark_full_validation() {
  docs=true
  governance=true
  go=true
  rust=true
  node=true
  windows=true
  linux=true
  ios=true
  apple=true
  workflow=true
  release_sensitive=true
  full_matrix=true
}

if [[ "${event_name}" == "workflow_dispatch" ]]; then
  change_source=workflow_dispatch
  mark_full_validation
elif [[ "${ref_type}" == "tag" ]]; then
  change_source=tag
  mark_full_validation
else
  diff_args=()
  if [[ "${event_name}" == "pull_request" ]]; then
    diff_args=("${base_sha}...${head_sha}")
  else
    diff_args=("${base_sha}" "${head_sha}")
  fi

  if [[ -z "${base_sha}" || -z "${head_sha}" || "${base_sha}" =~ ^0+$ ]] ||
    ! git cat-file -e "${base_sha}^{commit}" 2>/dev/null ||
    ! git cat-file -e "${head_sha}^{commit}" 2>/dev/null; then
    change_source=safe-default
    mark_full_validation
  else
    changed_files="${RUNNER_TEMP}/networkcore-ci-changed-files.txt"
    if ! git diff --name-only -z --diff-filter=ACMRDTUXB "${diff_args[@]}" > "${changed_files}"; then
      change_source=safe-default
      mark_full_validation
    else
      while IFS= read -r -d '' path; do
        [[ -n "${path}" ]] || continue
        changed_file_count=$((changed_file_count + 1))
        recognized=false

        case "${path}" in
          *.md|docs/*)
            mark docs
            recognized=true
            ;;
        esac

        case "${path}" in
          AGENT.md|AGENTS.md|CLAUDE.md|CONTRIBUTING.md|README.md|ROADMAP.md|TODO.md|CHANGELOG.md|docs/ci-cd-policy.md|.github/copilot-instructions.md)
            mark governance
            recognized=true
            ;;
        esac

        case "${path}" in
          .github/workflows/*|.github/scripts/*)
            mark workflow
            mark full_matrix
            recognized=true
            ;;
        esac

        case "${path}" in
          Cargo.toml|Cargo.lock|rust-toolchain|rust-toolchain.toml)
            mark rust
            mark full_matrix
            recognized=true
            ;;
          crates/*|apps/*/Cargo.toml|apps/*/build.rs|apps/*/src/*|apps/*/tests/*|third_party/*)
            if [[ "${path}" != *.md ]]; then
              mark rust
              recognized=true
            fi
            ;;
        esac

        case "${path}" in
          crates/platform-windows/*|crates/platform-linux/*|crates/platform-ios/*)
            ;;
          crates/*|third_party/*)
            if [[ "${path}" != *.md ]]; then
              mark full_matrix
            fi
            ;;
        esac

        case "${path}" in
          package.json|*/package.json|pnpm-lock.yaml|*/pnpm-lock.yaml|apps/windows-gui/ui/*)
            mark node
            recognized=true
            ;;
        esac

        case "${path}" in
          go.mod|*/go.mod|go.sum|*/go.sum|*.go|*/go.work|go.work)
            mark go
            mark full_matrix
            recognized=true
            ;;
        esac

        case "${path}" in
          apps/windows-cli/*|apps/windows-gui/*|apps/windows-service/*|crates/platform-windows/*|installer/windows/*)
            mark windows
            recognized=true
            ;;
        esac

        case "${path}" in
          apps/linux-cli/*|crates/platform-linux/*|docs/architecture/linux-*|docs/release-strategy.md)
            mark linux
            recognized=true
            ;;
        esac

        case "${path}" in
          apps/ios/*|crates/platform-ios/*|*.swift|*/Package.swift|Package.swift|*.xcodeproj/*|*.xcworkspace/*|*.entitlements|*/PrivacyInfo.xcprivacy|PrivacyInfo.xcprivacy|.github/workflows/*ios*|.github/workflows/*apple*)
            mark ios
            mark apple
            recognized=true
            ;;
        esac

        case "${path}" in
          .github/workflows/release.yml|docs/release-strategy.md|docs/manual-intervention.md|docs/architecture/*release*|docs/architecture/linux-package-*|installer/windows/*|LICENSE|Cargo.lock)
            mark release_sensitive
            mark full_matrix
            recognized=true
            ;;
        esac

        if [[ "${recognized}" == false ]]; then
          mark unknown
          mark full_matrix
        fi
      done < "${changed_files}"
    fi
  fi
fi

# A Rust path without a platform owner is shared by default and needs all runners.
if [[ "${rust}" == true && "${windows}" == false && "${linux}" == false && "${apple}" == false ]]; then
  full_matrix=true
fi

matrix_json() {
  local include_ubuntu="$1"
  local include_macos="$2"
  local include_windows="$3"
  local entries=()

  if [[ "${include_ubuntu}" == true ]]; then
    entries+=('{"os":"ubuntu-latest","timeout":30}')
  fi
  if [[ "${include_macos}" == true ]]; then
    entries+=('{"os":"macos-26","timeout":40}')
  fi
  if [[ "${include_windows}" == true ]]; then
    entries+=('{"os":"windows-latest","timeout":45}')
  fi
  if [[ "${#entries[@]}" -eq 0 ]]; then
    entries+=('{"os":"ubuntu-latest","timeout":30}')
  fi

  local joined
  joined="$(IFS=,; echo "${entries[*]}")"
  printf '{"include":[%s]}' "${joined}"
}

if [[ "${full_matrix}" == true ]]; then
  run_ubuntu=true
  run_macos=true
  run_windows=true
else
  run_ubuntu=false
  run_macos=false
  run_windows=false
  if [[ "${linux}" == true ]]; then run_ubuntu=true; fi
  if [[ "${apple}" == true || "${ios}" == true ]]; then run_macos=true; fi
  if [[ "${windows}" == true ]]; then run_windows=true; fi
fi

validation_matrix="$(matrix_json "${run_ubuntu}" "${run_macos}" "${run_windows}")"

groups=()
for group in docs governance go rust node windows linux ios apple workflow release_sensitive full_matrix unknown; do
  if [[ "${!group}" == true ]]; then
    groups+=("${group}")
  fi
done
if [[ "${#groups[@]}" -eq 0 ]]; then
  groups+=(none)
fi
group_list="$(IFS=,; echo "${groups[*]}")"

{
  echo "docs=${docs}"
  echo "governance=${governance}"
  echo "go=${go}"
  echo "rust=${rust}"
  echo "node=${node}"
  echo "windows=${windows}"
  echo "linux=${linux}"
  echo "ios=${ios}"
  echo "apple=${apple}"
  echo "workflow=${workflow}"
  echo "release_sensitive=${release_sensitive}"
  echo "full_matrix=${full_matrix}"
  echo "unknown=${unknown}"
  echo "change_source=${change_source}"
  echo "changed_file_count=${changed_file_count}"
  echo "groups=${group_list}"
  echo "validation_matrix=${validation_matrix}"
} >> "${GITHUB_OUTPUT}"

echo "change-source=${change_source}"
echo "changed-file-count=${changed_file_count}"
echo "changed-groups=${group_list}"
echo "validation-matrix=${validation_matrix}"
