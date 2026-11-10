#!/bin/bash
# Build WipePinGcc once per installed GCC, each with its own g++ and plugin
# headers, and say what each build gave.
#
#   build-matrix.sh --out DIR [--versions "10 11 12 13 14"] [--jobs 2]
#
# For each version N: `cmake -S compiler/gcc-repair -B DIR/gcc-repair-N -G Ninja
# -DCMAKE_CXX_COMPILER=g++-N` and `ninja -j <jobs>`, then the build's own
# canon-vectors on compiler/evidence/testdata/digest-vectors.json. A GCC plugin
# loads only into the GCC whose headers it was compiled against
# (plugin_default_version_check), so each version is a separate build with
# g++-N; the header directory is the one CMakeLists.txt asks g++-N for.
#
# There is no default output directory: where builds live is the caller's
# business, as for the fixture loop. The directory is resolved to an absolute
# path before anything is created, and one anywhere inside this repository is
# refused (exit 3, nothing made): build output does not belong in the tree. To
# keep the build on some CPUs, run the whole script under `taskset -c ...`;
# every child inherits it.
#
# Prints one tab-separated row per version (also written to DIR/build-matrix.tsv):
#   gcc  N  <g++-N --version, first line>  <plugin header dir>  <status>
#        <warnings>  <sha256 of libWipePinGcc.so>  <canon-vectors summary line>
# status: ok, skipped (no g++-N or no plugin headers for N), cmake_failed,
# build_failed or canon_failed. warnings is the number of `warning:` lines in
# the ninja log (the build is -Wall -Wextra). The cmake and ninja logs are
# DIR/gcc-repair-N.cmake.log and DIR/gcc-repair-N.ninja.log.
#
# Exit codes: 0 every requested version built with 0 warnings and its
# canon-vectors held; 2 at least one did not (or was skipped); 3 usage, or an
# --out that is refused.
set -u

HERE=$(cd "$(dirname "$0")" && pwd -P)
SRC=$(cd "$HERE/.." && pwd -P)
REPO=$(cd "$SRC/../.." && pwd -P)
VECTORS=$(cd "$SRC/../evidence/testdata" && pwd)/digest-vectors.json

OUT=
VERSIONS="10 11 12 13 14"
JOBS=2
usage() {
  echo "usage: build-matrix.sh --out DIR [--versions \"10 11 12 13 14\"] [--jobs N]" >&2
  exit 3
}
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT=${2:-}; shift 2 || usage ;;
    --versions) VERSIONS=${2:-}; shift 2 || usage ;;
    --jobs) JOBS=${2:-}; shift 2 || usage ;;
    *) usage ;;
  esac
done
[ -n "$OUT" ] || usage
case "$JOBS" in ''|*[!0-9]*) usage ;; esac
[ -f "$VECTORS" ] || { echo "build-matrix.sh: no digest vectors at $VECTORS" >&2; exit 3; }
for v in $VERSIONS; do
  case "$v" in ''|*[!0-9]*) echo "build-matrix.sh: not a version: $v" >&2; exit 3 ;; esac
done

# Resolve --out before creating anything: the deepest part of it that exists,
# with symbolic links resolved, then the rest as given. The rest may not step
# with `.` or `..`, which only an existing directory could resolve.
refuse_out() { echo "build-matrix.sh: refusing --out $OUT: $1" >&2; exit 3; }
case "$OUT" in /*) want=$OUT ;; *) want=$PWD/$OUT ;; esac
while [ "${want%/}" != "$want" ]; do want=${want%/}; done
[ -n "$want" ] || refuse_out "the root directory"
have=$want
rest=
while [ ! -d "$have" ]; do
  [ -e "$have" ] && refuse_out "$have exists and is not a directory"
  rest=/$(basename "$have")$rest
  have=$(dirname "$have")
done
case "$rest/" in */./*|*/../*) refuse_out "a part that does not exist yet steps with . or .." ;; esac
have=$(cd "$have" && pwd -P) || refuse_out "cannot enter it"
OUT=${have%/}$rest
# Inside this repository: by name, or because the existing part is the
# repository's root or a directory inside it under another spelling (a
# symbolic link, a case-folding file system).
case "$OUT/" in "$REPO"/*) refuse_out "it is inside this repository ($REPO)" ;; esac
d=$have
while :; do
  [ "$d" -ef "$REPO" ] && refuse_out "it is inside this repository ($REPO)"
  [ "$d" = / ] && break
  d=$(dirname "$d")
done
mkdir -p "$OUT" || refuse_out "cannot create it"

TSV="$OUT/build-matrix.tsv"
printf 'cc\tversion\tgxx\theaders\tstatus\twarnings\tsha256\tcanonVectors\n' > "$TSV"
failed=0
row() { printf '%s\n' "$1" >> "$TSV"; printf '%s\n' "$1"; }

for v in $VERSIONS; do
  gxx=$(g++-"$v" --version 2>/dev/null | head -n1)
  if [ -z "$gxx" ]; then
    row "$(printf 'gcc\t%s\t-\t-\tskipped\t-\t-\tno g++-%s' "$v" "$v")"
    failed=1; continue
  fi
  hdr=$(g++-"$v" -print-file-name=plugin 2>/dev/null)/include
  if [ ! -f "$hdr/gcc-plugin.h" ]; then
    row "$(printf 'gcc\t%s\t%s\t-\tskipped\t-\t-\tno plugin headers (gcc-%s-plugin-dev)' "$v" "$gxx" "$v")"
    failed=1; continue
  fi
  bd="$OUT/gcc-repair-$v"
  rm -rf "$bd"
  if ! cmake -S "$SRC" -B "$bd" -G Ninja -DCMAKE_CXX_COMPILER="g++-$v" > "$bd.cmake.log" 2>&1; then
    row "$(printf 'gcc\t%s\t%s\t%s\tcmake_failed\t-\t-\t-' "$v" "$gxx" "$hdr")"
    failed=1; continue
  fi
  if ! ninja -j "$JOBS" -C "$bd" > "$bd.ninja.log" 2>&1; then
    row "$(printf 'gcc\t%s\t%s\t%s\tbuild_failed\t%s\t-\t-' "$v" "$gxx" "$hdr" "$(grep -c 'warning:' "$bd.ninja.log")")"
    failed=1; continue
  fi
  warnings=$(grep -c 'warning:' "$bd.ninja.log")
  sha=$(sha256sum "$bd/libWipePinGcc.so" | cut -d' ' -f1)
  canon_all=$("$bd/canon-vectors" "$VECTORS" 2>&1)
  crc=$?
  canon=$(printf '%s\n' "$canon_all" | tail -n1)
  status=ok
  if [ $crc -ne 0 ] || ! printf '%s\n' "$canon" | grep -q ' 0 disagreed'; then
    status=canon_failed
  fi
  [ "$status" = ok ] && [ "$warnings" = 0 ] || failed=1
  row "$(printf 'gcc\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$v" "$gxx" "$hdr" "$status" "$warnings" "$sha" "$canon")"
done

[ $failed -eq 0 ] || exit 2
exit 0
