#!/usr/bin/env bash
# Build the introduction observer and measure with it.
#
# Everything it writes goes to the Linux filesystem, never under compiler/:
# interfaces.md §1, because a build directory reached over the mount is slow,
# takes CRLF ambiguity into digests, and bakes machine-specific paths into
# recorded output. Both directories are overridable so that a caller can put
# them wherever it keeps scratch; neither is written down as an absolute path
# here, because a build instruction carrying one machine's account name is both
# a disclosure and wrong for everyone else.
#
#   INTRO_BUILD_DIR   cmake -B target   (default $HOME/vg-build/pass-introduction)
#   INTRO_LAB_DIR     measurement output (default $HOME/vg-lab/pass-introduction)
#
# Usage:  tools/live.sh [build|measure|all]     (default: all)
#
# Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${INTRO_BUILD_DIR:-$HOME/vg-build/pass-introduction}"
LAB_DIR="${INTRO_LAB_DIR:-$HOME/vg-lab/pass-introduction}"
CC_BIN="${INTRO_CC:-clang-18}"
LLVM_CONFIG="${INTRO_LLVM_CONFIG:-llvm-config-18}"
PLUGIN="$BUILD_DIR/libIntroductionObserver.so"

step="${1:-all}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "live.sh: $1 is not on PATH. This is a failure, not a skip -- a" >&2
    echo "         measurement that did not run must not report as one." >&2
    exit 1
  }
}

do_build() {
  need cmake; need ninja; need "$LLVM_CONFIG"
  cmake -S "$HERE/.." -B "$BUILD_DIR" -G Ninja \
        -DLLVM_DIR="$("$LLVM_CONFIG" --cmakedir)" >/dev/null
  ninja -C "$BUILD_DIR" >/dev/null
  test -f "$PLUGIN" || { echo "live.sh: $PLUGIN was not produced" >&2; exit 1; }
  echo "built: $(basename "$PLUGIN")"
}

do_measure() {
  need "$CC_BIN"
  test -f "$PLUGIN" || { echo "live.sh: build first ($PLUGIN is missing)" >&2; exit 1; }
  mkdir -p "$LAB_DIR"
  local src="$HERE/../subjects/passes/introduced.c"
  local log="$LAB_DIR/passes.tsv"
  rm -f "$log" "$log.summary.tsv"

  INTRO_OUT="$log" \
  INTRO_CONTROL_FN="intro_pass_control" \
  INTRO_MODE="${INTRO_MODE:-standard}" \
    "$CC_BIN" -O2 -fpass-plugin="$PLUGIN" -c "$src" -o "$LAB_DIR/introduced.o"

  test -s "$log" || {
    echo "live.sh: the observer produced an empty log. An empty log is not a" >&2
    echo "         clean result -- the plugin did not install." >&2
    exit 1
  }

  # NON-INVASIVENESS. The claim is that the observer changes nothing about what
  # the compiler produces; this is the check that turns the claim into a
  # measurement. Same source, same flags, with and without the plugin, compared
  # byte for byte.
  "$CC_BIN" -O2 -c "$src" -o "$LAB_DIR/introduced.plain.o"
  if cmp -s "$LAB_DIR/introduced.o" "$LAB_DIR/introduced.plain.o"; then
    echo "non-invasive: object bytes identical with and without the plugin"
  else
    echo "live.sh: the object differs with the plugin loaded. The observer is" >&2
    echo "         not non-invasive and nothing it measured can be trusted." >&2
    exit 1
  fi

  echo "log: $log"
  echo "summary: $log.summary.tsv"
}

case "$step" in
  build) do_build ;;
  measure) do_measure ;;
  all) do_build; do_measure ;;
  *) echo "usage: live.sh [build|measure|all]" >&2; exit 2 ;;
esac
