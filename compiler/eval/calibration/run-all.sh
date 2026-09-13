#!/bin/bash
# The whole battery, in the one order that works.
#
#   bash compiler/eval/calibration/run-all.sh
#   bash compiler/eval/calibration/run-all.sh --no-falsify
#
# WHY THIS EXISTS
#
# The eight commands in README.md are order-dependent in a way that fails QUIETLY in
# one direction and loudly in the others. Assembling a report before its witness
# exists is exit 3, which is loud. But a grader run before a report was re-assembled
# reads the PREVIOUS report -- and that is the rubber-stamp path this directory found
# in itself and closed structurally, so the remaining exposure is a person running the
# steps out of order by hand. This script is the order, written down once.
#
# It is not a new capability and it decides nothing: every step is one of the four
# programs, invoked exactly as the README documents. What it adds is that a failing
# step STOPS the run. A sweep that carried on past a refused configuration would
# assemble a report for it from nothing, or grade the previous one as this one's.
#
# Configurations come from battery.json, not from this file. check-battery.py refuses
# when a declared configuration has no graded document, so a list here that had
# drifted from the table would produce a run that always fails -- or worse, a table
# entry nobody measures.
#
# EXIT CODES (interfaces.md section 7)
#   0  every configuration measured, assembled and graded; both graders clean. With
#      --no-falsify the last line says NOT ESTABLISHED instead: the step that shows
#      the graders REFUSING was skipped, and two clean graders is also what a
#      switched-off grader reports. The code does not move -- a flag a caller passed
#      on purpose is not a fault -- which is check-battery.py's own convention at its
#      `broken_seen == 0` branch, and the reason the last line has to differ
#   1  the toolchain refused an invocation; its diagnostics have already been printed
#   2  a grader found something: a reference cell misread its true value, an
#      invariant was falsified, or a catalogue sentence disagrees with the measurement
#   3  a step could not be completed
#
# The code is the FIRST failing step's, not a summary: 2 and 3 mean different things
# and a wrapper that merged them would tell a reader "something is wrong" and nothing
# more.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPTS="$HERE/scripts"
TABLE="$HERE/battery.json"
RUN_FALSIFY=1

for arg in "$@"; do
  case "$arg" in
    --no-falsify) RUN_FALSIFY=0 ;;
    *) echo "run-all.sh: unknown option $arg" >&2; exit 3 ;;
  esac
done

if [ ! -f "$TABLE" ]; then
  echo "run-all.sh: no cell table at $TABLE" >&2
  exit 3
fi

# The configurations the STANDARD declares, projected out of the table. Nothing else
# in this file knows what they are.
CONFIGS=$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
for c in d["configs"]:
    print("%s\t%s" % (c["configId"], c["opt"]))
' "$TABLE") || {
  echo "run-all.sh: could not read the configurations out of battery.json" >&2
  exit 3
}

if [ -z "$CONFIGS" ]; then
  echo "run-all.sh: battery.json declares no configurations, so this would sweep nothing" >&2
  exit 3
fi

step() { # description, command...
  local what=$1; shift
  printf '=== %s\n' "$what"
  "$@"
  local rc=$?
  if [ $rc -ne 0 ]; then
    echo "run-all.sh: STOPPED at: $what (exit $rc)" >&2
    echo "run-all.sh: later steps were not run, so nothing below this line was measured," >&2
    echo "run-all.sh: assembled or graded. A sweep that carried on would grade a previous" >&2
    echo "run-all.sh: run's report as this one's." >&2
    exit $rc
  fi
}

while IFS=$'\t' read -r CONFIG OPT; do
  [ -n "$CONFIG" ] || continue
  step "measure $CONFIG ($OPT)"  bash "$SCRIPTS/run-battery.sh" "$CONFIG" "$OPT"
  step "witness $CONFIG"         node "$SCRIPTS/witness-asm.mjs" "$CONFIG"
  step "assemble $CONFIG"        python3 "$SCRIPTS/build-battery-report.py" "$CONFIG"
done <<< "$CONFIGS"

# Graded only once every configuration is present, because check-battery.py's
# whole-set fence is what catches half a battery being reported as a whole one.
step "grade readings against known true values" python3 "$SCRIPTS/check-battery.py"
step "grade the catalogue's prose against the measurement" python3 "$SCRIPTS/check-claims.py"

if [ "$RUN_FALSIFY" = "1" ]; then
  # Last, and on the reports the run just produced. A grader that has never been
  # shown to fail has not been shown to work, and the demonstration is worth nothing
  # if it is not re-run with everything else.
  step "show the grader refusing corrupted reports" python3 "$SCRIPTS/falsify-battery.py"
fi

echo
echo "every configuration measured, assembled and graded; both graders clean."
echo "a battery pass is a SHAPE qualification -- necessary for promotion to"
echo "\`implemented\` in compiler/schema/properties.json and never sufficient, because"
echo "every cell here is a (synthetic-specimen, configuration) measurement."
# The falsify verdict goes LAST, after the qualification paragraph above. Until
# 2026-09-13 those three echoes came after the `fi`, which made the last line -- and
# the last three lines -- byte-identical with and without --no-falsify, while the
# comment in the else branch below cited check-battery.py on "what it changes is the
# last line". It did not change the last line. Found while the metamorphic lane next
# door copied this shape and inherited the same defect; both were corrected together.
if [ "$RUN_FALSIFY" = "1" ]; then
  # No count is written here on purpose. run-battery.sh's header says why in its
  # own words: an earlier version of it asserted "fifteen" and stayed saying it
  # after a sixteenth cell landed. falsify-battery.py prints how many corruptions
  # it applied and how many it skipped, and that line is the one to read.
  echo "check-battery.py was also shown REFUSING every applicable corruption above,"
  echo "each with the exit code interfaces.md section 7 assigns to it, on the reports"
  echo "this run produced. check-claims.py has no such demonstration and was not shown"
  echo "to refuse anything in any run."
else
  # NOT the same line as above, and this is the whole point of these four.
  #
  # --no-falsify skips the one step that shows the graders can refuse. Both graders
  # then exit 0 and this script exits 0, which is also what a grader with its
  # predicates inverted, its loop never entered or its return value discarded would
  # produce -- and until this line existed, the last thing a reader saw was
  # identical either way. compiler/eval/spike/lib/gate.mjs:178-183 refuses that
  # shape outright (INJECTION_NOT_DETECTED: "no injected configuration was run, so
  # the gate was never shown to go red"); this lane's own settled convention is
  # softer and is followed here instead of importing that one.
  #
  # It is deliberately NOT an error and does not move the exit code. That is
  # check-battery.py's own precedent, set at its `broken_seen == 0` branch and
  # stated there: "Not an error, and deliberately not an exit code. What it
  # changes is the last line, which is what a reader takes away." A flag a caller
  # passed on purpose is not a fault; a run whose last line hid what the flag
  # turned off would be.
  echo
  echo "NOT ESTABLISHED: --no-falsify was passed, so scripts/falsify-battery.py did not"
  echo "run and NOTHING IN THIS RUN WAS SHOWN TO REFUSE ANYTHING. A clean check-battery"
  echo "is also what a grader with its predicates inverted would report. Re-run without"
  echo "the flag before reading this as a qualification."
fi
