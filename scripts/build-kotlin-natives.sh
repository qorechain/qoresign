#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the qoresign-ffi native library for the Kotlin packages.
#
# Usage: scripts/build-kotlin-natives.sh [target...]
#
# Targets (default: host):
#   bindings             regenerate kotlin/src/main/kotlin/.../qoresign_ffi.kt
#   host                 the JNA target of this machine
#   darwin-aarch64       JVM jar resources: kotlin/natives/<target>/
#   darwin-x86-64
#   linux-x86-64
#   linux-aarch64
#   win32-x86-64
#   android-arm64-v8a    Android AAR jniLibs: kotlin/android/src/main/jniLibs/<abi>/
#   android-armeabi-v7a
#   android-x86_64
#   android              the three Android ABIs
#
# Android targets need ANDROID_NDK_HOME (NDK 27). Cross-compiling linux-aarch64
# from another architecture needs CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Keep build-machine paths out of the shipped binaries (panic locations and
# debug info would otherwise embed the local checkout and cargo home).
REMAP="--remap-path-prefix=$ROOT=/qoresign --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup"

CRATE=qoresign-ffi
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
JVM_OUT="$ROOT/kotlin/natives"
ANDROID_OUT="$ROOT/kotlin/android/src/main/jniLibs"
ANDROID_API="${ANDROID_API:-24}"

export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_STRIP=symbols
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"

host_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os/$arch" in
    Darwin/arm64) echo darwin-aarch64 ;;
    Darwin/x86_64) echo darwin-x86-64 ;;
    Linux/x86_64) echo linux-x86-64 ;;
    Linux/aarch64 | Linux/arm64) echo linux-aarch64 ;;
    MINGW*/x86_64 | MSYS*/x86_64 | CYGWIN*/x86_64) echo win32-x86-64 ;;
    *) echo "unsupported host $os/$arch" >&2; exit 1 ;;
  esac
}

host_lib() {
  case "$(uname -s)" in
    Darwin) echo libqoresign_ffi.dylib ;;
    Linux) echo libqoresign_ffi.so ;;
    *) echo qoresign_ffi.dll ;;
  esac
}

ndk_bin() {
  if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "ANDROID_NDK_HOME is not set" >&2
    exit 1
  fi
  local tag
  case "$(uname -s)" in
    Darwin) tag=darwin-x86_64 ;; # universal binaries
    Linux) tag=linux-x86_64 ;;
    *) tag=windows-x86_64 ;;
  esac
  echo "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$tag/bin"
}

# build_jvm <jna-prefix> <rust-target> <library file name>
build_jvm() {
  local prefix="$1" rust="$2" lib="$3"
  echo "==> $prefix ($rust)"
  RUSTFLAGS="$REMAP" cargo build --locked --release -p "$CRATE" --lib --target "$rust"
  mkdir -p "$JVM_OUT/$prefix"
  cp "$TARGET_DIR/$rust/release/$lib" "$JVM_OUT/$prefix/$lib"
}

# build_android <abi> <rust-target> <clang prefix>
build_android() {
  local abi="$1" rust="$2" clang="$3" bin env
  bin="$(ndk_bin)"
  env="$(echo "$rust" | tr '[:lower:]-' '[:upper:]_')"
  echo "==> android $abi ($rust, API $ANDROID_API)"
  export "CARGO_TARGET_${env}_LINKER=$bin/${clang}${ANDROID_API}-clang"
  # 16 KB page alignment, required by newer Android releases.
  export "CARGO_TARGET_${env}_RUSTFLAGS=-C link-arg=-Wl,-z,max-page-size=16384"
  export "CC_${rust//-/_}=$bin/${clang}${ANDROID_API}-clang"
  export "AR_${rust//-/_}=$bin/llvm-ar"
  RUSTFLAGS="$REMAP -C link-arg=-Wl,-z,max-page-size=16384" cargo build --locked --release -p "$CRATE" --lib --target "$rust"
  mkdir -p "$ANDROID_OUT/$abi"
  cp "$TARGET_DIR/$rust/release/libqoresign_ffi.so" "$ANDROID_OUT/$abi/libqoresign_ffi.so"
}

generate_bindings() {
  echo "==> Kotlin bindings"
  cargo build --locked -p "$CRATE" --lib
  cargo run --locked -p "$CRATE" --features cli --bin uniffi-bindgen -- \
    generate --library "$TARGET_DIR/debug/$(host_lib)" \
    --language kotlin --no-format --out-dir "$ROOT/kotlin/src/main/kotlin"
}

build() {
  case "$1" in
    bindings) generate_bindings ;;
    host) build "$(host_target)" ;;
    darwin-aarch64) build_jvm darwin-aarch64 aarch64-apple-darwin libqoresign_ffi.dylib ;;
    darwin-x86-64) build_jvm darwin-x86-64 x86_64-apple-darwin libqoresign_ffi.dylib ;;
    linux-x86-64) build_jvm linux-x86-64 x86_64-unknown-linux-gnu libqoresign_ffi.so ;;
    linux-aarch64) build_jvm linux-aarch64 aarch64-unknown-linux-gnu libqoresign_ffi.so ;;
    win32-x86-64) build_jvm win32-x86-64 x86_64-pc-windows-msvc qoresign_ffi.dll ;;
    android-arm64-v8a) build_android arm64-v8a aarch64-linux-android aarch64-linux-android ;;
    android-armeabi-v7a) build_android armeabi-v7a armv7-linux-androideabi armv7a-linux-androideabi ;;
    android-x86_64) build_android x86_64 x86_64-linux-android x86_64-linux-android ;;
    android)
      build android-arm64-v8a
      build android-armeabi-v7a
      build android-x86_64
      ;;
    *) echo "unknown target: $1" >&2; exit 2 ;;
  esac
}

if [ "$#" -eq 0 ]; then
  set -- host
fi
for t in "$@"; do
  build "$t"
done
