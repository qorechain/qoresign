#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds swift/QoreSignFFI.xcframework (iOS device, iOS simulator arm64+x86_64,
# macOS arm64+x86_64) from crates/qoresign-ffi, regenerates
# swift/Sources/QoreSign/QoreSign.swift, zips the xcframework and prints the
# SwiftPM checksum of the zip.
#
# Usage: scripts/build-xcframework.sh [--write-checksum]
#   --write-checksum  also writes the checksum into Package.swift (release step).
#
# Needs macOS with Xcode and the five Apple Rust targets installed. Set
# DEVELOPER_DIR when xcode-select points to the Command Line Tools.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Keep build-machine paths out of the shipped binaries (panic locations and
# debug info would otherwise embed the local checkout and cargo home).
REMAP="--remap-path-prefix=$ROOT=/qoresign --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup"

WRITE_CHECKSUM=0
for arg in "$@"; do
  case "$arg" in
    --write-checksum) WRITE_CHECKSUM=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

CRATE=qoresign-ffi
LIB=libqoresign_ffi.a
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
OUT="$ROOT/swift"
XCFRAMEWORK="$OUT/QoreSignFFI.xcframework"
ZIP="$OUT/QoreSignFFI.xcframework.zip"
WORK="$TARGET_DIR/xcframework"

export IPHONEOS_DEPLOYMENT_TARGET=16.0
export MACOSX_DEPLOYMENT_TARGET=13.0
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

TARGETS=(
  aarch64-apple-ios
  aarch64-apple-ios-sim
  x86_64-apple-ios
  aarch64-apple-darwin
  x86_64-apple-darwin
)

for t in "${TARGETS[@]}"; do
  echo "==> cargo build $t"
  RUSTFLAGS="$REMAP" cargo build --locked --release -p "$CRATE" --lib --target "$t"
done

rm -rf "$WORK"
mkdir -p "$WORK/bindings" "$WORK/headers/QoreSignFFI" "$WORK/ios-sim" "$WORK/macos"

echo "==> strip debug symbols"
for t in "${TARGETS[@]}"; do
  mkdir -p "$WORK/$t"
  cp "$TARGET_DIR/$t/release/$LIB" "$WORK/$t/$LIB"
  xcrun strip -S "$WORK/$t/$LIB"
done

echo "==> generate Swift bindings"
cargo run --locked -p "$CRATE" --features cli --bin uniffi-bindgen -- \
  generate --library "$TARGET_DIR/aarch64-apple-darwin/release/libqoresign_ffi.dylib" \
  --language swift --out-dir "$WORK/bindings"
cp "$WORK/bindings/QoreSign.swift" "$OUT/Sources/QoreSign/QoreSign.swift"
cp "$WORK/bindings/QoreSignFFI.h" "$WORK/headers/QoreSignFFI/QoreSignFFI.h"
# Headers live in a subdirectory named after the module so the module map
# does not collide with other xcframeworks in the same build.
cp "$WORK/bindings/QoreSignFFI.modulemap" "$WORK/headers/QoreSignFFI/module.modulemap"

echo "==> lipo"
lipo -create \
  "$WORK/aarch64-apple-ios-sim/$LIB" \
  "$WORK/x86_64-apple-ios/$LIB" \
  -output "$WORK/ios-sim/$LIB"
lipo -create \
  "$WORK/aarch64-apple-darwin/$LIB" \
  "$WORK/x86_64-apple-darwin/$LIB" \
  -output "$WORK/macos/$LIB"

echo "==> xcframework"
rm -rf "$XCFRAMEWORK" "$ZIP"
xcodebuild -create-xcframework \
  -library "$WORK/aarch64-apple-ios/$LIB" -headers "$WORK/headers" \
  -library "$WORK/ios-sim/$LIB" -headers "$WORK/headers" \
  -library "$WORK/macos/$LIB" -headers "$WORK/headers" \
  -output "$XCFRAMEWORK"

echo "==> zip"
(cd "$OUT" && ditto -c -k --sequesterRsrc --keepParent QoreSignFFI.xcframework QoreSignFFI.xcframework.zip)
CHECKSUM="$(swift package compute-checksum "$ZIP")"
echo "$CHECKSUM" > "$ZIP.sha256"

if [ "$WRITE_CHECKSUM" = 1 ]; then
  # Replaces the value of the `releaseChecksum` constant in Package.swift.
  sed -i.bak -E "s/^(let releaseChecksum = \")[^\"]*(\")/\1$CHECKSUM\2/" "$ROOT/Package.swift"
  rm -f "$ROOT/Package.swift.bak"
  echo "Package.swift checksum updated"
fi

echo
echo "xcframework: swift/QoreSignFFI.xcframework"
echo "zip:         swift/QoreSignFFI.xcframework.zip"
echo "checksum:    $CHECKSUM"
