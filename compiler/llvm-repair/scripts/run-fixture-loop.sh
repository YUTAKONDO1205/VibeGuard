#!/bin/bash
# The second, independent instrument for WipePin: the IR observer
# (compiler/llvm-pass, IrCheckpoints) watching the erasure fixture with and
# without the repair plugin loaded in the SAME clang invocation.
#
#   run-fixture-loop.sh --lab DIR --observer libIrCheckpoints.so --wipepin libWipePin.so
#
# (or WPIN_LAB / IRCK_PLUGIN / WPIN_PLUGIN in the environment). There are no
# default paths: where the lab and the builds live is the caller's business.
#
# Reads:   the fixtures written by compiler/llvm-pass/tools/make-fixtures.sh,
#          generated into <lab>/fixtures on every run -- never into the repo.
# Writes:  <lab>/records/<cell>.json     the observer's record (via observe.sh)
#          <lab>/wipepin/<cell>.json     WipePin's own record, where loaded
#          <lab>/cells/<cell>.kv         what ran, with both plugins' sha256
#          <lab>/stderr/<cell>.txt       clang's stderr for the cell
# Decides: nothing. check-fixture-loop.py grades, so the code that produces a
#          number is not the code that says whether it is the right one.
#
# The observer's -fpass-plugin comes FIRST on the command line and WipePin's
# second. Both register at the pipeline-start extension point, callbacks run in
# load order, so the observer's pre-optimisation checkpoint reads the IR before
# the pin is applied: the "pre" column is the unrepaired program in every cell.
#
# The effect-symbol list is the registered wipe-6 list, read by id from
# compiler/schema/effect-symbol-lists.json -- the list run-matrix.sh configures
# its erasure cells with -- rather than a copy of it, so that this loop and the
# matrix cannot be asking different questions about the same fixture.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
COMPILER=$(cd "$HERE/../.." && pwd)

LAB=${WPIN_LAB:-}
OBSERVER=${IRCK_PLUGIN:-}
WIPEPIN=${WPIN_PLUGIN:-}

usage() {
  echo "usage: run-fixture-loop.sh --lab DIR --observer libIrCheckpoints.so --wipepin libWipePin.so" >&2
  exit 3
}

while [ $# -gt 0 ]; do
  case "$1" in
    --lab) LAB=${2:-}; shift 2 || usage ;;
    --observer) OBSERVER=${2:-}; shift 2 || usage ;;
    --wipepin) WIPEPIN=${2:-}; shift 2 || usage ;;
    *) usage ;;
  esac
done
[ -n "$LAB" ] && [ -n "$OBSERVER" ] && [ -n "$WIPEPIN" ] || usage
for so in "$OBSERVER" "$WIPEPIN"; do
  [ -f "$so" ] || { echo "run-fixture-loop.sh: no plugin at $so" >&2; exit 3; }
done
mkdir -p "$LAB"
LAB=$(cd "$LAB" && pwd)

OBSERVE="$COMPILER/llvm-pass/scripts/observe.sh"
REGISTRY="$COMPILER/schema/effect-symbol-lists.json"

WIPE_LIST_ID=wipe-6
EFFECT_SYMBOLS=$(python3 - "$REGISTRY" "$WIPE_LIST_ID" <<'PY'
import json, sys
reg = json.load(open(sys.argv[1], encoding="utf-8"))
print(reg["lists"][sys.argv[2]]["literal"])
PY
)
if [ -z "$EFFECT_SYMBOLS" ]; then
  echo "run-fixture-loop.sh: could not read list $WIPE_LIST_ID from the registry" >&2
  exit 3
fi

IRCK_LAB="$LAB" bash "$COMPILER/llvm-pass/tools/make-fixtures.sh" >/dev/null
FX="$LAB/fixtures/erasure"
[ -f "$FX/target.c" ] || { echo "run-fixture-loop.sh: fixture generation failed" >&2; exit 3; }

mkdir -p "$LAB/wipepin" "$LAB/cells" "$LAB/stderr"
OBS_SHA=$(sha256sum "$OBSERVER" | cut -d' ' -f1)
PIN_SHA=$(sha256sum "$WIPEPIN" | cut -d' ' -f1)

failed=0

# cell <cell-id> <opt> <mode> [VAR=VAL ...]
#   mode  observer        observer only
#         observer+pin    observer, then WipePin, in one invocation
cell() {
  local id=$1 opt=$2 mode=$3
  shift 3
  local rec="$LAB/wipepin/$id.json"
  rm -f "$rec"
  local extra=()
  local pinenv=()
  if [ "$mode" = "observer+pin" ]; then
    extra=(-fpass-plugin="$WIPEPIN")
    pinenv=(WPIN_OUT="$rec" "$@")
  fi
  # env -u: nothing from the caller's environment may configure WipePin in a
  # cell that did not ask for it, and nothing may leak from one cell into the
  # next (the reason run-matrix.sh uses env rather than prefix assignments).
  env -u WPIN_OUT -u WPIN_TARGET_FNS -u WPIN_SCOPE -u WPIN_DRY_RUN \
      IRCK_LAB="$LAB" IRCK_PLUGIN="$OBSERVER" \
      OBS_EXTRACTOR=ir.wipe-effect \
      OBS_PROPERTY_ID=erasure.wipe \
      OBS_TARGET_FN=handle_request \
      OBS_CONTROL_FN=wipe_kept \
      OBS_EFFECT_SYMBOLS="$EFFECT_SYMBOLS" \
      OBS_FIXTURE_REL=erasure/target.c \
      "${pinenv[@]+"${pinenv[@]}"}" \
      bash "$OBSERVE" "$id" "$FX" target.c "$opt" "${extra[@]+"${extra[@]}"}" \
      > /dev/null 2> "$LAB/stderr/$id.txt"
  local rc=$?
  local pinrec=absent
  [ -s "$rec" ] && pinrec=present
  {
    echo "cellId=$id"
    echo "opt=$opt"
    echo "mode=$mode"
    echo "observeRc=$rc"
    echo "observerSha256=$OBS_SHA"
    if [ "$mode" = "observer+pin" ]; then
      echo "wipepinSha256=$PIN_SHA"
      echo "wipepinRecord=$pinrec"
      echo "wipepinEnv=$*"
    else
      echo "wipepinSha256=not-loaded"
      echo "wipepinRecord=not-loaded"
      echo "wipepinEnv="
    fi
    echo "effectSymbolList=$WIPE_LIST_ID"
  } > "$LAB/cells/$id.kv"
  if [ $rc -ne 0 ] || { [ "$mode" = "observer+pin" ] && [ "$pinrec" != present ]; }; then
    echo "run-fixture-loop.sh: $id: observe rc=$rc, WipePin record $pinrec" >&2
    failed=1
  fi
  echo "$id"
}

for O in -O0 -O1 -O2 -O3; do
  cell "base$O" "$O" observer
  cell "pin$O" "$O" observer+pin WPIN_TARGET_FNS=handle_request
done

# The red control: the plugin loaded and configured exactly as above, but told
# to change nothing. If the loss does not come back here, whatever made the
# pin cells PRESENT was not the volatile flag.
cell "dry-O2" -O2 observer+pin WPIN_TARGET_FNS=handle_request WPIN_DRY_RUN=1

# The misspelt name. The plugin loads, writes a well-formed record, pins
# nothing, and the loss must come back -- with the misspelling on record.
cell "wrongname-O2" -O2 observer+pin WPIN_TARGET_FNS=handle_requestX

if [ $failed -ne 0 ]; then
  echo "run-fixture-loop.sh: at least one cell did not produce its records" >&2
  exit 3
fi
exit 0
