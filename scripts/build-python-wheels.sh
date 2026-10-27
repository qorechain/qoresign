#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the Python package qorechain-qoresign (python/) from crates/qoresign-ffi
# with maturin (UniFFI bindings) and checks that no build-machine path ends up
# in the wheels.
#
# Usage: scripts/build-python-wheels.sh [target...]
#
# Targets (default: host):
#   host            wheel for this machine
#   macos-arm64     macOS 11+ arm64 wheel
#   macos-x86_64    macOS 11+ x86_64 wheel
#   sdist           source distribution
#   check           only check the files already in python/dist
#
# Output: python/dist/. Needs maturin (python/requirements-dev.txt) on PATH and
# the Rust target of each wheel. Linux (manylinux2014) and Windows wheels are
# built in CI (.github/workflows/release.yml).
#
# The wheels are tagged py3-none-<platform>: the bindings load the native
# library through ctypes and do not use the CPython ABI, so one wheel per
# platform covers every Python 3 version.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Keep build-machine paths out of the shipped binaries (panic locations and
# debug info would otherwise embed the local checkout and cargo home).
REMAP="--remap-path-prefix=$ROOT=/qoresign --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup"

PY="$ROOT/python"
DIST="$PY/dist"
MATURIN_VERSION="$(sed -nE 's/^requires = \["maturin==([^"]+)"\]/\1/p' "$PY/pyproject.toml")"
# Paths that must not appear in anything shipped, besides the checkout itself.
FORBIDDEN='/Users/|/home/|/root/|[A-Za-z]:\\+Users\\+|runneradmin'
ROOT_NATIVE="$(cygpath -w "$ROOT" 2> /dev/null || echo "$ROOT")"

export RUSTFLAGS="$REMAP"
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_STRIP=symbols
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"

check_maturin() {
  local found
  found="$(maturin --version | awk '{print $2}')"
  if [ "$found" != "$MATURIN_VERSION" ]; then
    echo "maturin $MATURIN_VERSION required, found $found (pip install -r python/requirements-dev.txt)" >&2
    exit 1
  fi
}

# The wheel and the sdist carry the repository LICENSE and NOTICE.
license_files() {
  cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$PY/"
}

wheel() {
  echo "==> wheel ${1:-host}"
  (cd "$PY" && maturin build --release --locked --out "$DIST" ${1:+--target "$1"})
}

sdist() {
  echo "==> sdist"
  (cd "$PY" && maturin sdist --out "$DIST")
}

# unzip where available (Git Bash on Windows may lack it), else Python.
unzip_to() {
  if command -v unzip > /dev/null; then
    unzip -q "$1" -d "$2"
  else
    "$(command -v python3 || command -v python)" -m zipfile -e "$1" "$2"
  fi
}

# Number of lines of $1 that contain a forbidden path or the checkout path.
count_paths() {
  local n m
  n="$(LC_ALL=C grep -a -c -E "$FORBIDDEN" "$1" || true)"
  m="$(LC_ALL=C grep -a -c -F -e "$ROOT" -e "$ROOT_NATIVE" "$1" || true)"
  echo $((n + m))
}

# Every file in the tree $1; native libraries are reported one by one.
check_tree() {
  local label="$1" dir="$2" bad=0 f n
  while IFS= read -r -d '' f; do
    n="$(count_paths "$f")"
    case "$f" in
      *.so | *.dylib | *.dll | *.pyd) echo "$label $(basename "$f"): $n local path(s)" ;;
    esac
    case "$f" in
      *.map) echo "$label: source map ${f#"$dir"/}"; bad=1 ;;
    esac
    if [ "$n" != 0 ]; then
      echo "$label: local path in ${f#"$dir"/}"
      bad=1
    fi
  done < <(find "$dir" -type f -print0)
  return "$bad"
}

check_paths() {
  local work bad=0 f
  work="$(mktemp -d)"
  shopt -s nullglob
  for f in "$DIST"/*.whl "$DIST"/*.tar.gz; do
    rm -rf "${work:?}"/*
    case "$f" in
      *.whl) unzip_to "$f" "$work" ;;
      *) tar -xzf "$f" -C "$work" ;;
    esac
    check_tree "$(basename "$f")" "$work" || bad=1
  done
  shopt -u nullglob
  rm -rf "$work"
  if [ "$bad" != 0 ]; then
    echo "build-machine paths found in python/dist" >&2
    exit 1
  fi
  echo "no build-machine paths in python/dist"
}

build() {
  case "$1" in
    host) wheel ;;
    macos-arm64) wheel aarch64-apple-darwin ;;
    macos-x86_64) wheel x86_64-apple-darwin ;;
    sdist) sdist ;;
    check) ;;
    *) echo "unknown target: $1" >&2; exit 2 ;;
  esac
}

if [ "$#" -eq 0 ]; then
  set -- host
fi
if [ "$*" != check ]; then
  check_maturin
  license_files
fi
for t in "$@"; do
  build "$t"
done
check_paths
echo
ls -l "$DIST"
