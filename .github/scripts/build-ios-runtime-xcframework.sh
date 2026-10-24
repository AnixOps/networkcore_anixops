#!/usr/bin/env bash
# Builds engine-embedded as a static XCFramework for the iOS packet tunnel.
# Runs only in GitHub Actions on macos-26; the output is never committed.
#
# Usage: build-ios-runtime-xcframework.sh [device|all]
#   device: iPhone slice only (archive and upload)
#   all:    iPhone plus simulator slices (default, CI Xcode build)
#
# Output: apps/ios/Generated/NetworkCoreRuntime.xcframework, whose headers expose the
# Clang module NetworkCoreRuntimeC to the NetworkCorePacketTunnel target.
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
out="${root}/apps/ios/Generated/NetworkCoreRuntime.xcframework"
work="${RUNNER_TEMP:-${root}/target}/networkcore-ios-runtime"
lib=libengine_embedded.a

device_target=aarch64-apple-ios
sim_targets=(aarch64-apple-ios-sim x86_64-apple-ios)
targets=("${device_target}")
if [[ "${slices}" == all ]]; then
  targets+=("${sim_targets[@]}")
fi

rustup target add "${targets[@]}"

# Matches the app's deployment target; release settings keep the extension binary small.
export IPHONEOS_DEPLOYMENT_TARGET=17.0
export CARGO_PROFILE_RELEASE_LTO=thin
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_DEBUG=0

# rquickjs (MITM scripts) ships no iOS bindings; bindgen generates them against the matching SDK.
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_apple_ios="-isysroot $(xcrun --sdk iphoneos --show-sdk-path)"
simulator_sdk="$(xcrun --sdk iphonesimulator --show-sdk-path)"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_apple_ios_sim="-isysroot ${simulator_sdk}"
export BINDGEN_EXTRA_CLANG_ARGS_x86_64_apple_ios="-isysroot ${simulator_sdk}"

for target in "${targets[@]}"; do
  cargo build --locked --release -p engine-embedded --lib --target "${target}"
done

rm -rf "${work}" "${out}"
mkdir -p "${work}/headers" "${work}/device" "$(dirname "${out}")"
cp "${root}/crates/engine-embedded/include/networkcore_ios_runtime.h" "${work}/headers/"
cat > "${work}/headers/module.modulemap" <<'EOF'
module NetworkCoreRuntimeC {
    header "networkcore_ios_runtime.h"
    export *
}
EOF

cp "${root}/target/${device_target}/release/${lib}" "${work}/device/${lib}"
args=(-library "${work}/device/${lib}" -headers "${work}/headers")

if [[ "${slices}" == all ]]; then
  mkdir -p "${work}/simulator"
  sim_libs=()
  for target in "${sim_targets[@]}"; do
    sim_libs+=("${root}/target/${target}/release/${lib}")
  done
  lipo -create "${sim_libs[@]}" -output "${work}/simulator/${lib}"
  args+=(-library "${work}/simulator/${lib}" -headers "${work}/headers")
fi

xcodebuild -create-xcframework "${args[@]}" -output "${out}"

# Linkage of the C ABI is checked on the built extension binary by the CI Xcode job; Xcode's nm cannot
# always read archives produced by Rust's newer LLVM.
du -sh "${work}/device/${lib}"
echo "Built ${out} (${slices})"
