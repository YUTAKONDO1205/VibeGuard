#!/bin/bash
# The whole lane, in the one order that works.
#
#   bash compiler/eval/metamorphic/run-all.sh
#   bash compiler/eval/metamorphic/run-all.sh --no-falsify
#
# WHY THIS EXISTS
#
# Until 2026-09-13 README.md's four steps were a list a person followed, and step 4
# -- `scripts/falsify-meta.py`, the demonstration that the grader can refuse -- was
# the one nothing ever invoked. A run that stopped after step 3 was graded by an
# ungraded grader, and the last thing on the screen was
# "all N document(s) satisfy the relations declared in catalogue.json", which is
# also exactly what a grader with its predicates inverted would print. The lane's
# own README said so in capitals, which is a sentence, and a sentence is a thing a
# person remembers. compiler/eval/calibration/run-all.sh had already drawn this
# conclusion for its own battery; this is the same conclusion for this lane.
#
# It is not a new capability and it decides nothing: every step is one of the four
# programs, invoked exactly as README.md documents. What it adds is that a failing
# step STOPS the run, that the configurations come from the catalogue rather than
# from this file, and that the falsifier is inside the sweep instead of beside it.
#
# Configurations come from catalogue.json's `configurations`, not from this file.
# This script sweeps whatever the table declares and enforces only one half of the
# pairing: a sweep that holds only `-O0` is refused by check-meta.py (exit 3, the
# survival-axis fence) because no R2b cell moves there. The other half is NOT
# enforced at run time -- a table declaring only `-O2` sweeps and grades clean here,
# and nothing in this run would say that R1 invariance was never checked where the
# optimiser has done nothing. That half is a STATIC fence instead:
# test/catalogue.test.mjs asserts the table carries at least one configuration with
# r2bCanMove true AND at least one with it false, which CI runs and this script does
# not. Said plainly because an earlier version of this comment claimed "both, from
# the table, every time", which is what the table says and not what this file checks.
#
# EXIT CODES (interfaces.md section 7)
#   0  every configuration measured, assembled and graded; the grader clean. With
#      --no-falsify the last line says NOT ESTABLISHED instead: the step that shows
#      the grader REFUSING was skipped, and a clean grader is also what a
#      switched-off one reports. The code does not move -- a flag a caller passed on
#      purpose is not a fault -- which is calibration/run-all.sh's convention at the
#      same branch, and the reason the last line has to differ
#   1  the toolchain refused an invocation; its diagnostics have already been printed
#   2  the grader found a disagreement: a relation was falsified, or a cell landed
#      somewhere its declared direction does not reach
#   3  a step could not be completed -- including a sweep in which nothing on the
#      survival axis ever moved, and a results directory holding a document no
#      configuration in the catalogue accounts for
#   5  this script could not be set up: no catalogue, a catalogue that declares no
#      configuration, or one that declares no configuration at which an R2b cell can
#      move. interfaces.md section 7
#
# The code is the FIRST failing step's, not a summary: 2 and 3 mean different things
# and a wrapper that merged them would tell a reader "something is wrong" and nothing
# more.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPTS="$HERE/scripts"
CATALOGUE="$HERE/catalogue.json"
LAB=${VG_META_LAB:-$HOME/vg-lab/metamorphic}
REPORTS=${VG_META_OUT:-$LAB/_results}
RUN_FALSIFY=1

for arg in "$@"; do
  case "$arg" in
    --no-falsify) RUN_FALSIFY=0 ;;
    *) echo "run-all.sh: unknown option $arg" >&2; exit 5 ;;
  esac
done

if [ ! -f "$CATALOGUE" ]; then
  echo "run-all.sh: no catalogue at $CATALOGUE" >&2
  exit 5
fi

# The configurations the CATALOGUE declares, projected out of it. Nothing else in
# this file knows what they are. The r2bCanMove check is here and not left to
# check-meta.py because a catalogue edited down to configurations at which no R2b
# cell can move describes a lane that can never qualify, and finding that out from
# a refused grade at the end of a sweep is finding it out late.
CONFIGS=$(python3 "$SCRIPTS/read-configurations.py" "$CATALOGUE") || {
  echo "run-all.sh: could not read the configurations out of catalogue.json" >&2
  exit 5
}

if [ -z "$CONFIGS" ]; then
  echo "run-all.sh: catalogue.json declares no configurations, so this would sweep nothing" >&2
  exit 5
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
    echo "run-all.sh: run's document as this one's." >&2
    exit $rc
  fi
}

while IFS=$'\t' read -r RUN OPT; do
  [ -n "$RUN" ] || continue
  step "measure $RUN ($OPT)"  bash "$SCRIPTS/run-metamorphic.sh" "$RUN" "$OPT"
  step "assemble $RUN"        python3 "$SCRIPTS/build-meta-report.py" "$RUN"
done <<< "$CONFIGS"

# Before the grade: a document in $VG_META_OUT that no declared configuration
# accounts for would be swept and graded as part of this run. It is nobody's
# measurement in this sweep -- a leftover from a run id that has since been removed
# from the catalogue, or from another lab pointed at the same directory -- and a
# sweep that silently includes it reports a grade over a set its own table does not
# describe. Refused rather than deleted: this script does not own that directory.
step "account for every document in $REPORTS" \
  python3 "$SCRIPTS/account-for-documents.py" "$REPORTS" "$CATALOGUE"

# Graded only once every configuration is present, because check-meta.py's whole-set
# survival-axis fence is what catches half a sweep being reported as a whole one --
# and because that fence only fires when the grader is given no arguments, which is
# how it is invoked here.
step "grade the relations declared in catalogue.json" python3 "$SCRIPTS/check-meta.py"

if [ "$RUN_FALSIFY" = "1" ]; then
  # Last, and on the documents the run just produced. A grader that has never been
  # shown to fail has not been shown to work, and the demonstration is worth nothing
  # if it is not re-run with everything else. This is the step whose absence from any
  # automatic sequence is the reason this file exists.
  step "show the grader refusing corrupted documents" python3 "$SCRIPTS/falsify-meta.py"
fi

echo
echo "every configuration in catalogue.json measured, assembled and graded; the grader clean."
echo "a clean sweep is a RELATION qualification -- it says the declared directions held"
echo "over property-shaped specimens at the configurations catalogue.json declares, and"
echo "never that a property is implemented: that word is compiler/schema/properties.json's."
# The falsify verdict goes LAST, after the qualification paragraph above, because the
# whole point of the --no-falsify branch is that the run's final line differs. The
# first version of this script printed those three echoes after the `fi`, which made
# the last line -- and the last THREE lines -- byte-identical either way, while this
# file's own header claimed they differed. calibration/run-all.sh had the same
# ordering and the same claim; both were corrected on 2026-09-13.
if [ "$RUN_FALSIFY" = "1" ]; then
  # No count is written here on purpose. falsify-meta.py prints how many corruptions
  # it applied and how many it skipped as not applicable to the document in hand, and
  # that line is the one to read -- a number asserted here would stay saying what it
  # said after a tenth corruption landed.
  echo "check-meta.py was also shown REFUSING every applicable corruption above, each"
  echo "with the exit code interfaces.md section 7 assigns to it, on the documents this"
  echo "run produced."
else
  # NOT the same line as above, and that is the whole point of these four.
  #
  # --no-falsify skips the one step that shows the grader can refuse. check-meta.py
  # then exits 0 and this script exits 0, which is also what a grader with its
  # predicates inverted, its loop never entered or its return value discarded would
  # produce. calibration/run-all.sh says the same thing at the same branch and for
  # the same reason, and states there why this is deliberately not an error and
  # deliberately does not move the exit code.
  echo
  echo "NOT ESTABLISHED: --no-falsify was passed, so scripts/falsify-meta.py did not run"
  echo "and NOTHING IN THIS RUN WAS SHOWN TO REFUSE ANYTHING. A clean check-meta is also"
  echo "what a grader with its predicates inverted would report. Re-run without the flag"
  echo "before reading this as a qualification."
fi
