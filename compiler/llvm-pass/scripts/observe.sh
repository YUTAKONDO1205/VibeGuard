#!/bin/bash
# One cell: compile one translation unit with the observer loaded, and leave a
# record behind. Nothing here interprets the record -- check-matrix.py does that,
# so that the thing which decides pass or fail is not the thing which produced
# the number.
#
#   observe.sh <cell-id> <fixture-dir> <source> <opt> [extra clang args...]
#
# Everything else comes from OBS_* in the environment. Build and measurement
# output go to $IRCK_LAB (default ~/vg-lab/llvm-pass); nothing is written under
# compiler/.
set -u

CELL=${1:?cell id}
FIXTURE=${2:?fixture dir}
SRC=${3:?source file}
OPT=${4:?opt level}
shift 4

LAB=${IRCK_LAB:-$HOME/vg-lab/llvm-pass}
PLUGIN=${IRCK_PLUGIN:-$HOME/vg-build/llvm-pass/libIrCheckpoints.so}
CC=${IRCK_CC:-clang-18}

mkdir -p "$LAB/records" "$LAB/snapshots/$CELL" "$LAB/objects"

export OBS_OUT="$LAB/records/$CELL.json"
export OBS_SNAPSHOT_DIR="$LAB/snapshots/$CELL"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1700000000}

rm -f "$OBS_OUT"

"$CC" "$OPT" -fpass-plugin="$PLUGIN" -c "$FIXTURE/$SRC" \
      -o "$LAB/objects/$CELL.o" "$@"
rc=$?
if [ $rc -ne 0 ]; then
  echo "observe.sh: $CELL: compiler exited $rc" >&2
  exit 1          # exit 1 is "the underlying tool failed" (interfaces.md section 7)
fi
if [ ! -s "$OBS_OUT" ]; then
  echo "observe.sh: $CELL: no record was written; the observation did not happen" >&2
  exit 3          # exit 3 is "a check could not be completed", never 0
fi
echo "$CELL -> ${OBS_OUT#"$LAB/"}"
