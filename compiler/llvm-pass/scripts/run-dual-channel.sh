#!/bin/bash
# Produce the dual-channel records. Decides nothing -- check-dual-channel.py
# does that, so the thing that produces the number is not the thing that grades
# it.
#
#   bash compiler/llvm-pass/scripts/run-dual-channel.sh
#   python3 compiler/llvm-pass/scripts/check-dual-channel.py
#
# Reads:   $IRCK_DUAL_LAB/fixtures (written by tools/make-dual-channel-fixtures.sh)
# Writes:  $IRCK_DUAL_LAB (default ~/vg-lab/llvm-pass-dual)
#
# The lab is its own directory and the plugin defaults to its own build
# directory, so this cannot overwrite the optimisation matrix's records or its
# build.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
LAB=${IRCK_DUAL_LAB:-$HOME/vg-lab/llvm-pass-dual}
PLUGIN=${IRCK_PLUGIN:-$HOME/vg-build/llvm-pass-dualchannel/libIrCheckpoints.so}
CC=${IRCK_CC:-clang-18}

if [ ! -f "$PLUGIN" ]; then
  echo "run-dual-channel.sh: no plugin at $PLUGIN" >&2
  echo "  cmake -S compiler/llvm-pass -B ~/vg-build/llvm-pass-dualchannel -G Ninja \\" >&2
  echo "        -DLLVM_DIR=\$(llvm-config-18 --cmakedir) && ninja -C ~/vg-build/llvm-pass-dualchannel" >&2
  exit 3
fi

bash "$HERE/../tools/make-dual-channel-fixtures.sh" >/dev/null || exit 3
FX="$LAB/fixtures"

WIPE_SYMS="llvm.memset,memset,explicit_bzero,bzero,__memset_chk,memset_s"

mkdir -p "$LAB/records" "$LAB/objects" "$LAB/snapshots"

fail=0

# cell <id> <fixture> <opt> <subject> [extra OBS_ assignments...]
cell() {
  local id=$1 fixture=$2 opt=$3 subject=$4
  shift 4
  local out="$LAB/records/$id.json"
  rm -f "$out"
  mkdir -p "$LAB/snapshots/$id"
  # `env` rather than a prefix assignment in front of a shell function: in bash
  # a prefix on a function call persists in the calling shell, and the cell that
  # exists to be pointed at the wrong vocabulary is exactly the one whose
  # configuration must not leak into the next.
  env OBS_EXTRACTOR=ir.wipe-effect \
      OBS_PROPERTY_ID=erasure.wipe \
      OBS_TARGET_FN="$subject" \
      OBS_CONTROL_FN=wipe_kept \
      OBS_EFFECT_SYMBOLS="$WIPE_SYMS" \
      OBS_FIXTURE_REL="$fixture/target.c" \
      OBS_OUT="$out" \
      OBS_SNAPSHOT_DIR="$LAB/snapshots/$id" \
      SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}" \
      "$@" \
      "$CC" "$opt" -fpass-plugin="$PLUGIN" -c "$FX/$fixture/target.c" \
      -o "$LAB/objects/$id.o"
  rc=$?
  if [ $rc -ne 0 ]; then
    echo "run-dual-channel.sh: $id: compiler exited $rc" >&2
    fail=1
    return
  fi
  if [ ! -s "$out" ]; then
    echo "run-dual-channel.sh: $id: no record was written" >&2
    fail=1
    return
  fi
  echo "$id -> records/$id.json"
}

# --- the four cells of the pair ---------------------------------------------
# Subject A at -O0 and at the levels where the optimiser can fold the block the
# annotation lives in. -O0 is not decoration: without it, "the annotation went"
# has no baseline saying it was ever there.
cell dual-red-O0 dual -O0 red_subject
cell dual-red-O1 dual -O1 red_subject
cell dual-red-O2 dual -O2 red_subject
cell dual-red-O3 dual -O3 red_subject

cell dual-both-survive-O0 dual -O0 both_survive
cell dual-both-survive-O2 dual -O2 both_survive

cell dual-metadata-lies-O0 dual -O0 metadata_lies
cell dual-metadata-lies-O2 dual -O2 metadata_lies

cell dual-both-erased-O0 dual -O0 both_erased
cell dual-both-erased-O2 dual -O2 both_erased

# --- the two cells that exist so the headline state cannot be a default ------
# Pointed at a vocabulary nothing in the module carries. The metadata channel
# must then say it measured nothing, not that something was erased.
cell dual-wrong-prefix-O2 dual -O2 red_subject \
     OBS_ANNOTATION_PREFIX=nothing:carries:this

# The same program with the annotations removed from the source.
cell dual-no-annotation-O2 plain -O2 red_subject

exit $fail
