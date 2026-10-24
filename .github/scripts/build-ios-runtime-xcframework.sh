#!/usr/bin/env bash
# Builds engine-embedded as a static XCFramework for the iOS and macOS packet tunnels,
# and node-import as a second one for the iOS containing app (subscription import
# without the tunnel engine). Runs only in GitHub Actions on macos-26; the output is
# never committed.
#
# Usage: build-ios-runtime-xcframework.sh [device|all]
#   device: iPhone slice only (archive and upload)
#   all:    iPhone, simulator and universal macOS slices (default, CI Xcode build)
#
# Output: apps/ios/Generated/NetworkCoreRuntime.xcframework, whose headers expose the
# Clang module NetworkCoreRuntimeC to the NetworkCorePacketTunnel and NetworkCoreMacTunnel targets,
# and apps/ios/Generated/NetworkCoreImport.xcframework (module NetworkCoreImportC) for
# the NetworkCoreApp target.
set -euo pipefail

slices="${1:-all}"
case "${slices}" in
  device | all) ;;
  *)
    echo "::error::usage: build-ios-runtime-xcframework.sh [device|all]"
    exit 2
    ;;
esac

root="$(git rev-parse --show-toplevel)"

device_target=aarch64-apple-ios
sim_targets=(aarch64-apple-ios-sim x86_64-apple-ios)
mac_targets=(aarch64-apple-darwin x86_64-apple-darwin)
targets=("${device_target}")
if [[ "${slices}" == all ]]; then
  targets+=("${sim_targets[@]}" "${mac_targets[@]}")
fi

rustup target add "${targets[@]}"

# Matches the apps' deployment targets; release settings keep the extension binary small.
export IPHONEOS_DEPLOYMENT_TARGET=17.0
export MACOSX_DEPLOYMENT_TARGET=14.0
export CARGO_PROFILE_RELEASE_LTO=thin
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_DEBUG=0

for target in "${targets[@]}"; do
  cargo build --locked --release -p engine-embedded -p node-import --lib --target "${target}"
done

# package <crate dir> <library file> <header> <module> <xcframework name>
package() {
  local crate="$1" lib="$2" header="$3" module="$4" name="$5"
  local out="${root}/apps/ios/Generated/${name}.xcframework"
  local work="${RUNNER_TEMP:-${root}/target}/networkcore-ios-${name}"
  rm -rf "${work}" "${out}"
  # Each module map sits in a directory named after its module: Xcode copies every linked
  # XCFramework's headers into the same include/ directory, so two top-level module maps collide.
  mkdir -p "${work}/headers/${module}" "${work}/device" "$(dirname "${out}")"
  cp "${root}/crates/${crate}/include/${header}" "${work}/headers/${module}/"
  printf 'module %s {\n    header "%s"\n    export *\n}\n' "${module}" "${header}" > "${work}/headers/${module}/module.modulemap"

  cp "${root}/target/${device_target}/release/${lib}" "${work}/device/${lib}"
  local args=(-library "${work}/device/${lib}" -headers "${work}/headers")

  if [[ "${slices}" == all ]]; then
    mkdir -p "${work}/simulator"
    local sim_libs=()
    for target in "${sim_targets[@]}"; do
      sim_libs+=("${root}/target/${target}/release/${lib}")
    done
    lipo -create "${sim_libs[@]}" -output "${work}/simulator/${lib}"
    args+=(-library "${work}/simulator/${lib}" -headers "${work}/headers")

    mkdir -p "${work}/macos"
    local mac_libs=()
    for target in "${mac_targets[@]}"; do
      mac_libs+=("${root}/target/${target}/release/${lib}")
    done
    lipo -create "${mac_libs[@]}" -output "${work}/macos/${lib}"
    args+=(-library "${work}/macos/${lib}" -headers "${work}/headers")
  fi

  xcodebuild -create-xcframework "${args[@]}" -output "${out}"

  # Linkage of the C ABI is checked on the built binaries by the CI Xcode job; Xcode's nm cannot
  # always read archives produced by Rust's newer LLVM.
  du -sh "${work}/device/${lib}"
  echo "Built ${out} (${slices})"
}

package engine-embedded libengine_embedded.a networkcore_ios_runtime.h NetworkCoreRuntimeC NetworkCoreRuntime
package node-import libnode_import.a networkcore_import.h NetworkCoreImportC NetworkCoreImport
