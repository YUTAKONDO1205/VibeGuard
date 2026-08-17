#!/bin/bash
# One exposure of the calibration battery: every cell in battery.json through the
# real observer, plus one independent assembly listing per cell.
#
# The count is deliberately not written here. An earlier version of this header said
# "fifteen", and stayed saying it after a sixteenth cell landed -- a tracked file
# asserting something untrue about the table beside it. The table is the only place
# the number lives; this script projects it and prints what it observed.
#
#   bash compiler/eval/calibration/scripts/run-battery.sh <config-id> <opt> [extra clang args...]
#
#   bash compiler/eval/calibration/scripts/run-battery.sh O0 -O0
#   bash compiler/eval/calibration/scripts/run-battery.sh O2 -O2
#
# Reads:   ../battery.json (the cell table) and $VG_CAL_LAB/fixtures
# Writes:  $VG_CAL_LAB (default ~/vg-lab/calibration)
# Decides: NOTHING. It leaves one record and one assembly listing per cell, plus a
#          manifest. Whether a reading agrees with the battery's known true value
#          is scripts/check-battery.py's job, and that file is the only one that
#          opens claims/expected.json. The thing that produces a reading is not
#          the thing that reads it, and here it is also not the thing that holds
#          the answers.
#
# WHY THE ASSEMBLY LISTING IS TAKEN IN THE SAME RUN
#
# Half of this battery's true values stand on a reading of the emitted assembly --
# a stack frame too small to hold the object, a function label that is no longer
# in the listing, an indirect call where the source wrote a direct one. That leg
# has to come from the SAME invocation as the record, or the two are readings of
# two compilations and the witness witnesses nothing. It is compiled WITHOUT the
# pass plugin: an independent channel that shares the instrument under test is not
# independent.
#
# EXIT CODES (interfaces.md section 7)
#   0  every cell of this configuration produced a record and a listing
#   1  the toolchain refused an invocation. Its diagnostics pass through
#      unchanged, as section 7 requires of a 1.
#   3  the run could not be made -- no compiler, no plugin, no specimen, a drifted
#      standard, a name the specimen does not define, an LTO token -- or was made
#      and left no record. "Could not look" is never a pass, so every refusal
#      below leaves 3 and never 0, and the reason word is written into the
#      manifest as well as onto stderr.
#
# A cell that fails STOPS the run rather than being skipped. A short battery is not
# this battery, and a caller that received 0 with a cell missing would be comparing
# a shorter battery against a longer one without being told -- the same argument
# run-ladder.sh makes about eleven rungs.
set -u

CONFIG=${1:?config id}
OPT=${2:?opt level}
shift 2
EXTRA=("$@")

HERE=$(cd "$(dirname "$0")" && pwd)
TABLE="$HERE/../battery.json"
GENERATOR="$HERE/../tools/make-battery.sh"
LAB=${VG_CAL_LAB:-$HOME/vg-lab/calibration}
PLUGIN=${IRCK_PLUGIN:-$HOME/vg-build/llvm-pass/libIrCheckpoints.so}
CC=${IRCK_CC:-clang-18}

export LC_ALL=C

# The config id names a directory and a manifest file, so it is checked before it
# is used as one rather than after.
case "$CONFIG" in
  *[!A-Za-z0-9._-]*|""|.|..|-*)
    echo "run-battery.sh: config id '$CONFIG' is not a plain name" >&2
    exit 3
    ;;
esac

FX="$LAB/fixtures"
RECORDS="$LAB/records/$CONFIG"
ASM="$LAB/asm/$CONFIG"
MANIFEST="$LAB/configs/$CONFIG.kv"

mkdir -p "$LAB/configs" "$LAB/objects" "$LAB/stderr" "$RECORDS" "$ASM"

# Emptied before anything else happens, refusals included. A manifest with a
# non-zero rc must never sit beside a previous run's records, or the assembler
# reads somebody else's configuration as this one's.
rm -f "$RECORDS"/*.json "$ASM"/*.s
# And so must everything DOWNSTREAM of the records, for a reason that was measured
# rather than reasoned about. Before this line existed, a refused run left the
# previous run's witness and report in place, and the whole chain then said:
#
#   run-battery.sh O2 -O2 -flto   -> exit 3, records/O2 emptied
#   witness-asm.mjs O2            -> exit 3
#   build-battery-report.py O2    -> exit 3
#   check-battery.py              -> EXIT 0, "all 2 document(s) satisfy the
#                                    invariants in this file ... not a
#                                    switched-off grader reporting silence"
#
# byte-identical to a healthy run, because a stale report is internally consistent
# and its digest recomputes. Three exit-3s in a scrolled-past shell were the only
# trace. That is precisely the failure this directory exists to detect, produced by
# this directory, so the fix is structural: a refused run leaves NO report, and
# check-battery.py then has nothing to grade and exits 3 rather than 0.
rm -f "$LAB/witness/$CONFIG.json" "$LAB/_results/calibration/$CONFIG.json"

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1700000000}

sanitise() { sed -e "s#$HOME#~#g" -e "s#$LAB#<lab>#g"; }

GENERATOR_SHA=$(sha256sum "$GENERATOR" | cut -d' ' -f1)
PLUGIN_SHA=absent
[ -f "$PLUGIN" ] && PLUGIN_SHA=$(sha256sum "$PLUGIN" | cut -d' ' -f1)
# `absent` rather than empty until the compiler has been found and asked. An empty
# value is the one thing a downstream reader treats as "this manifest makes no
# claim about the compiler" and skips its checks over, so the manifest of a run
# that never found a compiler would read as the manifest of a run that got
# further than it did. No clang version is a substring of `absent`.
CC_VERSION=absent
STANDARD_REVISION=absent
CELLS=0
OBSERVED=0
REFUSAL=

emit_manifest() { # rc
  {
    echo "configId=$CONFIG"
    echo "opt=$OPT"
    echo "cc=$CC"
    echo "ccVersion=$CC_VERSION"
    echo "standardRevision=$STANDARD_REVISION"
    echo "generator=eval/calibration/tools/make-battery.sh"
    echo "generatorSha256=$GENERATOR_SHA"
    echo "pluginSha256=$PLUGIN_SHA"
    echo "cellCount=$CELLS"
    echo "cellsObserved=$OBSERVED"
    echo "records=records/$CONFIG"
    echo "asm=asm/$CONFIG"
    echo "sourceDateEpoch=$SOURCE_DATE_EPOCH"
    echo "refusal=$REFUSAL"
    echo "rc=$1"
    printf 'argvB64=%s\n' \
      "$(printf '%s\n' "$OPT" "${EXTRA[@]+"${EXTRA[@]}"}" | sanitise | base64 -w0)"
  } > "$MANIFEST"
}

finish() { # rc
  emit_manifest "$1"
  exit "$1"
}

# --- refusals, before anything is compiled -----------------------------------

# An LTO token is refused rather than measured, for the reason run-ladder.sh gives
# at length: the plugin registers on the pipeline-start and optimizer-last
# extension points, which the LTO backend pipeline does not invoke, so what a
# -flto compile can be observed doing is the prelink stage only. A prelink reading
# offered as this configuration's calibration would answer for a pipeline nothing
# looked at. It is a 3 because the check could not be made, not a 0 because
# nothing went wrong.
for arg in "$OPT" "${EXTRA[@]+"${EXTRA[@]}"}"; do
  case "$arg" in
    -flto*)
      echo "run-battery.sh: $CONFIG: refusing '$arg': lto-stage-unobserved" >&2
      REFUSAL=lto-stage-unobserved
      finish 3
      ;;
  esac
done

if [ ! -f "$TABLE" ]; then
  echo "run-battery.sh: no cell table at $TABLE" >&2
  REFUSAL=table-absent
  finish 3
fi

if [ ! -f "$PLUGIN" ]; then
  echo "run-battery.sh: no plugin at $PLUGIN" >&2
  echo "  cmake -S compiler/llvm-pass -B ~/vg-build/llvm-pass -G Ninja \\" >&2
  echo "        -DLLVM_DIR=\$(llvm-config-18 --cmakedir) && ninja -C ~/vg-build/llvm-pass" >&2
  REFUSAL=plugin-absent
  finish 3
fi

# Checked by name beside the plugin, before the first cell is compiled. Without
# this an IRCK_CC that does not resolve arrives as the shell's own "command not
# found" on the first compile, rc=127, which the loop below would report as exit 1
# under the word `toolchain-refused-invocation` -- and a toolchain that was never
# there refused nothing.
if ! command -v "$CC" >/dev/null 2>&1; then
  echo "run-battery.sh: '$CC' (IRCK_CC) does not resolve to a command" >&2
  REFUSAL=compiler-absent
  finish 3
fi

CC_VERSION_LINE=$("$CC" --version | head -1)
if [ -z "$CC_VERSION_LINE" ]; then
  echo "run-battery.sh: '$CC --version' printed nothing, so the manifest cannot name the compiler that ran" >&2
  REFUSAL=compiler-version-unreadable
  finish 3
fi
CC_VERSION=$CC_VERSION_LINE

# --- the standard, and its pin ------------------------------------------------
#
# A calibration standard whose specimens can change between two runs is not a
# standard. The generator's digest is recomputed here and held against the value
# battery.json carries; a mismatch is refused rather than recorded, because a
# report assembled over a drifted standard is comparable with nothing and looks
# comparable with everything.

PINNED_SHA=$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as exc:
    print("READ-ERROR " + str(exc))
    sys.exit(0)
print(d.get("generatorSha256", "MISSING"))
print(d.get("standardRevision", "MISSING"))
' "$TABLE") || {
  echo "run-battery.sh: could not read $TABLE" >&2
  REFUSAL=table-unreadable
  finish 3
}
STANDARD_REVISION=$(printf '%s\n' "$PINNED_SHA" | sed -n 2p)
PINNED_SHA=$(printf '%s\n' "$PINNED_SHA" | sed -n 1p)

if [ "$PINNED_SHA" != "$GENERATOR_SHA" ]; then
  echo "run-battery.sh: the standard has drifted: calibration-standard-drifted" >&2
  echo "  battery.json generatorSha256 = $PINNED_SHA" >&2
  echo "  tools/make-battery.sh        = $GENERATOR_SHA" >&2
  echo "  A generator that changed is a different standard. Update battery.json's" >&2
  echo "  generatorSha256 and standardRevision in the same commit as the generator," >&2
  echo "  so that a reviewer sees the standard move rather than inferring it." >&2
  REFUSAL=calibration-standard-drifted
  finish 3
fi

# --- the specimens, and the cell table checked against them -------------------

GEN_OUT=$(bash "$GENERATOR")
rc=$?
if [ $rc -ne 0 ]; then
  echo "run-battery.sh: $CONFIG: make-battery.sh exited $rc" >&2
  printf '%s\n' "$GEN_OUT" >&2
  REFUSAL=specimens-not-generated
  finish 3
fi

# The names the emitted files actually define, from the generator's own reading of
# its own output, keyed by fixture. A cell naming a function that is not in this
# list would not fail: the observer would resolve nothing, exit 0, write a record
# whose control held, and leave only the subject's rows empty -- a reading
# indistinguishable at a glance from a property that was never there. Checking the
# table against the emitted bytes is what turns that third silent failure mode
# into a refusal.
DEFINED_KEYED=" $(printf '%s\n' "$GEN_OUT" | sed -n 's/^fn=//p' | tr '\n' ' ')"
if [ "$DEFINED_KEYED" = " " ]; then
  echo "run-battery.sh: $CONFIG: the generator emitted no function names at all, so every name check below would pass vacuously" >&2
  REFUSAL=defined-function-list-empty
  finish 3
fi

# The cell table, projected to one line per cell. Only the measurement columns are
# read; nothing in expected.json is opened by this script.
CELL_LINES=$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
shapes = d["shapes"]
for c in d["cells"]:
    shape = shapes[c["shape"]]
    syms = c.get("symbols") or shape["symbols"]
    print("|".join([c["fixtureId"], c["shape"], shape["extractor"],
                    c["subjectFn"], c["controlFn"], syms, c["sourceRel"]]))
' "$TABLE") || {
  echo "run-battery.sh: could not project the cell table out of $TABLE" >&2
  REFUSAL=table-unreadable
  finish 3
}

if [ -z "$CELL_LINES" ]; then
  echo "run-battery.sh: $TABLE declares no cells" >&2
  REFUSAL=table-empty
  finish 3
fi

CELLS=$(printf '%s\n' "$CELL_LINES" | wc -l)

while IFS='|' read -r ID SHAPE EXTRACTOR SUBJ CTL SYMS SRCREL; do
  for fn in "$SUBJ" "$CTL"; do
    case "$DEFINED_KEYED" in
      *" $ID:$fn "*) ;;
      *)
        echo "run-battery.sh: $CONFIG: cell $ID names $fn, which $ID's emitted specimen does not define" >&2
        REFUSAL=specimen-function-missing
        finish 3
        ;;
    esac
  done
done <<< "$CELL_LINES"

# --- one observation and one independent listing per cell --------------------

while IFS='|' read -r ID SHAPE EXTRACTOR SUBJ CTL SYMS SRCREL; do
  RECORD="$RECORDS/$ID.json"
  LISTING="$ASM/$ID.s"
  ERRFILE="$LAB/stderr/$CONFIG-$ID.txt"
  rm -f "$RECORD" "$LISTING" "$ERRFILE"

  SRCDIR="$FX/$(dirname "$SRCREL")"
  SRCFILE=$(basename "$SRCREL")

  if [ ! -s "$SRCDIR/$SRCFILE" ]; then
    echo "run-battery.sh: $CONFIG/$ID: no specimen at fixtures/$SRCREL" >&2
    REFUSAL=specimen-absent
    finish 3
  fi

  # Run from the specimen's directory with a relative input, so the module
  # identifier in every record is the bare file name and not a path through
  # somebody's home directory. The module identifier is inside the evidence
  # digest, so an absolute path there would make two labs disagree about a digest
  # for a reason that has nothing to do with the configuration being read.
  cd "$SRCDIR" || {
    echo "run-battery.sh: $CONFIG/$ID: cannot enter the specimen's directory" >&2
    REFUSAL=specimen-absent
    finish 3
  }

  # Exactly one symbol list is set: ir.forbidden-callee reads
  # OBS_FORBIDDEN_SYMBOLS and the other two read OBS_EFFECT_SYMBOLS. Every other
  # knob is REMOVED rather than left alone -- an OBS_REQUIRE_LIVE_BRANCH exported
  # by whoever called this script would change the guarded cells, and an
  # OBS_SNAPSHOT_DIR would write this run's IR into another run's directory. A
  # configuration that leaks from one observation into the next is the bug this
  # component exists to catch elsewhere.
  OBS=(OBS_EXTRACTOR="$EXTRACTOR"
       OBS_PROPERTY_ID="calibration.$ID"
       OBS_TARGET_FN="$SUBJ"
       OBS_CONTROL_FN="$CTL"
       OBS_FIXTURE_REL="$SRCREL"
       OBS_OUT="$RECORD")
  if [ "$EXTRACTOR" = "ir.forbidden-callee" ]; then
    OBS+=(OBS_FORBIDDEN_SYMBOLS="$SYMS")
  else
    OBS+=(OBS_EFFECT_SYMBOLS="$SYMS")
  fi

  env -u OBS_EFFECT_SYMBOLS -u OBS_FORBIDDEN_SYMBOLS -u OBS_SNAPSHOT_DIR \
      -u OBS_REQUIRE_LIVE_BRANCH -u OBS_DISABLE_MEMOBJ_DISCRIMINATOR \
      -u OBS_ANNOTATION_PREFIX \
      "${OBS[@]}" \
      "$CC" "$OPT" "${EXTRA[@]+"${EXTRA[@]}"}" -fpass-plugin="$PLUGIN" \
      -c "$SRCFILE" -o "$LAB/objects/$CONFIG-$ID.o" 2> "$ERRFILE"
  rc=$?

  if [ $rc -ne 0 ]; then
    echo "run-battery.sh: $CONFIG/$ID: compiler exited $rc; its diagnostics follow (copy in stderr/$CONFIG-$ID.txt)" >&2
    if [ -s "$ERRFILE" ]; then
      cat "$ERRFILE" >&2
    else
      echo "run-battery.sh: $CONFIG/$ID: the compiler exited $rc and printed no diagnostic" >&2
    fi
    REFUSAL=toolchain-refused-invocation
    finish 1
  fi

  # The observer's second silent failure: a rejected OBS_* leaves the plugin
  # unregistered, the compiler exits 0 and nothing at all is measured. A wrapper
  # that forwarded that 0 would report an unexamined cell as examined. The
  # captured stderr is emitted with the refusal because the plugin writes its
  # reason for not installing there and lets the compile succeed, and a refusal
  # whose stated cause sits in a file the caller was only given the name of is
  # reported worse than it was diagnosed.
  if [ ! -s "$RECORD" ]; then
    echo "run-battery.sh: $CONFIG/$ID: the compile succeeded and no record was written" >&2
    if [ -s "$ERRFILE" ]; then
      echo "run-battery.sh: $CONFIG/$ID: what the compiler said (copy in stderr/$CONFIG-$ID.txt):" >&2
      cat "$ERRFILE" >&2
    fi
    REFUSAL=observer-wrote-no-record
    finish 3
  fi

  # The independent leg. No plugin, same compiler, same flags, same run. A witness
  # taken from a different invocation is a witness to a different compilation.
  "$CC" "$OPT" "${EXTRA[@]+"${EXTRA[@]}"}" -S "$SRCFILE" -o "$LISTING" \
      2> "$LAB/stderr/$CONFIG-$ID-asm.txt"
  rc=$?
  if [ $rc -ne 0 ] || [ ! -s "$LISTING" ]; then
    echo "run-battery.sh: $CONFIG/$ID: the assembly listing could not be produced (rc=$rc)" >&2
    [ -s "$LAB/stderr/$CONFIG-$ID-asm.txt" ] && cat "$LAB/stderr/$CONFIG-$ID-asm.txt" >&2
    REFUSAL=witness-listing-absent
    finish 3
  fi

  OBSERVED=$((OBSERVED + 1))
  printf '%-22s %-10s %s\n' "$ID" "$SHAPE" "records/$CONFIG/$ID.json"
done <<< "$CELL_LINES"

echo "$CONFIG: $OBSERVED of $CELLS cells under ${LAB#"$HOME/"}/records/$CONFIG"
# Said out loud because a run that ends here has measured a configuration and
# concluded nothing about it, and the last line of a run is where that is easiest
# to miss.
echo "records and listings only -- no report, no grading, no verdict."
finish 0
