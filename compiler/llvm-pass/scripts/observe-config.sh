#!/bin/bash
# One envelope cell: the same observation the optimisation matrix makes, taken
# under a named build configuration instead of only a named optimisation level.
#
#   observe-config.sh <cell-id> <fixture-dir> <source> <opt> <ndebug> <lto> <target> <freestanding>
#
#     ndebug        0 | 1                -- whether -DNDEBUG is on the command line
#     lto           none | full-prelink | thin-prelink | full-backend | thin-backend
#     target        host | arm-none-eabi | aarch64-none-elf
#     freestanding  0 | 1                -- whether -ffreestanding is on the command line
#
# Everything else comes from OBS_* in the environment, exactly as observe.sh
# wants it. Compile-stage cells are handed to observe.sh unchanged rather than
# reimplemented here, so the envelope measures the same compile the matrix does
# and the two cannot drift apart.
#
# This script decides nothing. It writes a key=value manifest next to the record
# so that build-envelope.py can say what configuration produced which reading --
# a record alone does not carry its own invocation, which is the whole gap the
# configuration envelope exists to close.
#
# Exit codes follow interfaces.md section 7:
#   0  the observation happened and a record exists
#   1  the toolchain refused the invocation (UNSUPPORTED)
#   3  the toolchain accepted it and no record was written (BROKEN_MEASUREMENT)
#
# There is no fourth case, and in particular there is no path on which this
# script returns 0 without a record. The observer has a known failure mode in
# which a missing OBS_* leaves the plugin unregistered, the compiler exits 0, and
# nothing at all is measured; a wrapper that forwarded that 0 would report a
# build as checked that was never looked at.
set -u

CELL=${1:?cell id}
FIXTURE=${2:?fixture dir}
SRC=${3:?source file}
OPT=${4:?opt level}
NDEBUG=${5:?ndebug 0|1}
LTO=${6:?lto mode}
TARGET=${7:?target}
FREESTANDING=${8:?freestanding 0|1}

HERE=$(cd "$(dirname "$0")" && pwd)
LAB=${IRCK_LAB:-$HOME/vg-lab/llvm-pass}
PLUGIN=${IRCK_PLUGIN:-$HOME/vg-build/llvm-pass/libIrCheckpoints.so}
CC=${IRCK_CC:-clang-18}
ARM_SYSROOT=${IRCK_ARM_SYSROOT:-$HOME/vg-lab/toolchains/gcc-arm-none-eabi-10.3-2021.10/arm-none-eabi}

mkdir -p "$LAB/cells" "$LAB/records" "$LAB/objects" "$LAB/stderr"

RECORD="$LAB/records/$CELL.json"
ERRFILE="$LAB/stderr/$CELL.txt"
MANIFEST="$LAB/cells/$CELL.kv"

rm -f "$RECORD" "$ERRFILE"

# Paths that leave this script are relative or tilde-shortened. The lab lives
# under a home directory whose name is not this repository's business, and
# check-matrix.py already fails a record that carries an absolute path.
sanitise() { sed -e "s#$HOME#~#g" -e "s#$LAB#<lab>#g"; }

# --- turn the configuration into command-line arguments ----------------------
EXTRA=()
[ "$NDEBUG" = "1" ] && EXTRA+=(-DNDEBUG)
[ "$FREESTANDING" = "1" ] && EXTRA+=(-ffreestanding)

case "$TARGET" in
  host) ;;
  arm-none-eabi)
    EXTRA+=(--target=arm-none-eabi -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
            --sysroot="$ARM_SYSROOT")
    ;;
  aarch64-none-elf)
    # No sysroot is shipped for this one. It is in the sweep so that the answer
    # to "does the envelope cover aarch64" is a recorded refusal rather than an
    # absence someone can read as a pass.
    EXTRA+=(--target=aarch64-none-elf)
    ;;
  *) echo "observe-config.sh: $CELL: unknown target $TARGET" >&2; exit 1 ;;
esac

LTO_COMPILE=()
STAGE=compile
case "$LTO" in
  none) ;;
  full-prelink) LTO_COMPILE+=(-flto) ;;
  thin-prelink) LTO_COMPILE+=(-flto=thin) ;;
  full-backend) LTO_COMPILE+=(-flto);      STAGE=link ;;
  thin-backend) LTO_COMPILE+=(-flto=thin); STAGE=link ;;
  *) echo "observe-config.sh: $CELL: unknown lto mode $LTO" >&2; exit 1 ;;
esac
EXTRA+=("${LTO_COMPILE[@]+"${LTO_COMPILE[@]}"}")

PLUGIN_SHA=absent
[ -f "$PLUGIN" ] && PLUGIN_SHA=$(sha256sum "$PLUGIN" | cut -d' ' -f1)

emit_manifest() { # rc
  {
    echo "cellId=$CELL"
    echo "subject=${CELL_SUBJECT:-unnamed}"
    echo "propertyId=${OBS_PROPERTY_ID:-unnamed}"
    echo "extractor=${OBS_EXTRACTOR:-ir.wipe-effect}"
    echo "subjectUnit=${OBS_TARGET_FN:-}"
    echo "controlUnit=${OBS_CONTROL_FN:-}"
    echo "opt=$OPT"
    echo "ndebug=$NDEBUG"
    echo "lto=$LTO"
    echo "target=$TARGET"
    echo "freestanding=$FREESTANDING"
    echo "stage=$STAGE"
    echo "cc=$CC"
    echo "rc=$1"
    echo "pluginSha256=$PLUGIN_SHA"
    echo "expectedBroken=${CELL_EXPECTED_BROKEN:-0}"
    echo "expectedBrokenReason=${CELL_EXPECTED_BROKEN_REASON:-}"
    if [ -s "$RECORD" ]; then echo "record=records/$CELL.json"; else echo "record="; fi
    printf 'extraArgsB64=%s\n' \
      "$(printf '%s\n' "${EXTRA[@]+"${EXTRA[@]}"}" | sanitise | base64 -w0)"
    printf 'stderrB64=%s\n' \
      "$( [ -s "$ERRFILE" ] && head -c 2000 "$ERRFILE" | sanitise | base64 -w0 )"
  } > "$MANIFEST"
}

finish() { # rc
  emit_manifest "$1"
  exit "$1"
}

# --- compile-stage cells: hand straight to observe.sh ------------------------
if [ "$STAGE" = "compile" ]; then
  bash "$HERE/observe.sh" "$CELL" "$FIXTURE" "$SRC" "$OPT" \
       "${EXTRA[@]+"${EXTRA[@]}"}" > /dev/null 2> "$ERRFILE"
  rc=$?
  # observe.sh already distinguishes 1 from 3; anything else is a wrapper bug and
  # must not be laundered into a pass.
  case $rc in
    0|1|3) ;;
    *) rc=3 ;;
  esac
  if [ $rc -eq 0 ] && [ ! -s "$RECORD" ]; then rc=3; fi
  finish $rc
fi

# --- link-stage cells: the LTO backend ---------------------------------------
# The bitcode is compiled WITHOUT the plugin on purpose. If the compile step
# loaded it, the compile would write the record and the link would find nothing
# to overwrite -- and this cell would report a pre-link reading under a
# backend label, which is the exact false attribution the LTO axis exists to
# avoid. Compiling clean means any record found afterwards can only have come
# from the linker, and build-envelope.py checks the module identifier to say so.
BC="$LAB/objects/$CELL.d"
rm -rf "$BC"; mkdir -p "$BC"
: > "$ERRFILE"

for unit in main.c opaque.c "$SRC"; do
  [ -f "$FIXTURE/$unit" ] || continue
  "$CC" "$OPT" -c "$FIXTURE/$unit" -o "$BC/${unit%.c}.o" \
        "${EXTRA[@]+"${EXTRA[@]}"}" >> "$ERRFILE" 2>&1 || finish 1
done

LINK_ARGS=("$OPT" "${EXTRA[@]+"${EXTRA[@]}"}" -fuse-ld=lld
           "-Wl,--load-pass-plugin=$PLUGIN")
# The observer keeps one recorder per process. A parallel ThinLTO backend would
# have several modules writing into it at once, so the job count is pinned to
# one; a cell that cannot pin it is not measured at all.
[ "$LTO" = "thin-backend" ] && LINK_ARGS+=(-Wl,--thinlto-jobs=1)

rm -f "$RECORD"
mkdir -p "$LAB/snapshots/$CELL"
export OBS_OUT="$RECORD"
export OBS_SNAPSHOT_DIR="$LAB/snapshots/$CELL"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1700000000}
"$CC" "${LINK_ARGS[@]}" "$BC"/*.o -o "$BC/a.out" >> "$ERRFILE" 2>&1
rc=$?
if [ $rc -ne 0 ]; then finish 1; fi
if [ ! -s "$RECORD" ]; then
  echo "observe-config.sh: $CELL: the link succeeded and no record was written" >> "$ERRFILE"
  finish 3
fi
finish 0
