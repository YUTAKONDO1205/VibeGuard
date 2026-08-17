#!/bin/bash
# One exposure, twelve observations: the ladder specimen compiled under a build's own
# command line, through the real observer.
#
#   bash compiler/llvm-pass/scripts/run-ladder.sh <exposure-id> <opt> [extra clang args...]
#
#   bash compiler/llvm-pass/scripts/run-ladder.sh O2 -O2
#   bash compiler/llvm-pass/scripts/run-ladder.sh F3 -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
#
# Reads:   $IRCK_LADDER_LAB/fixtures/ladder (written here by tools/make-ladder.sh)
# Writes:  $IRCK_LADDER_LAB (default ~/vg-lab/llvm-pass-ladder)
# Decides: NOTHING. It leaves twelve records and one manifest. Reading one
#          exposure's rungs against another's -- exposure-mismatch,
#          exposure-consistent, exposure-incomparable -- is the grader's job, so
#          the thing that produces the reading is not the thing that reads it.
#          In particular nothing here compares two exposures, and nothing here
#          may be pointed at an envelope cell: a ladder rung is a
#          (ladder-subject, configuration) measurement and says nothing at all
#          about the user's subject.
#
# Why this exists: the fallback envelope is keyed by a NOMINAL six-axis
# configuration, and a command line carrying -D_FORTIFY_SOURCE=3, or
# -fno-builtin-memset, or -ffast-math produces the same key as plain -O2 while
# producing a different optimiser. Measured on 2026-08-17, those three change
# what this specimen's rungs do; the key does not move. The ladder is the
# instrument that says so, per build, from a measurement rather than from a
# table.
#
# The specimen is a separate translation unit compiled with -c into a lab
# outside the repository. The build under test is not recompiled and none of its
# objects are read or written, so its bytes are identical whether or not this
# ran.
#
# Exit codes follow interfaces.md section 7:
#   0  twelve records exist
#   1  the toolchain refused the invocation, and its diagnostics are passed
#      through to stderr unchanged, as section 7 requires of a 1
#   3  the run could not be made -- no compiler, no plugin, no specimen, an LTO
#      token -- or was made and left no record
# "Could not look" is never a pass, so every refusal below leaves 3 and never 0,
# and the reason word is written into the manifest as well as onto stderr.
#
# A rung that fails stops the run rather than being skipped: eleven records are
# not a frontier, and a caller that received 0 with a rung missing would be
# comparing a shorter ladder against a longer one without being told.
set -u

EXPOSURE=${1:?exposure id}
OPT=${2:?opt level}
shift 2
EXTRA=("$@")

HERE=$(cd "$(dirname "$0")" && pwd)
LAB=${IRCK_LADDER_LAB:-$HOME/vg-lab/llvm-pass-ladder}
PLUGIN=${IRCK_PLUGIN:-$HOME/vg-build/llvm-pass/libIrCheckpoints.so}
CC=${IRCK_CC:-clang-18}

# The exposure id names a directory and a manifest file, so it is checked before
# it is used as one rather than after.
case "$EXPOSURE" in
  *[!A-Za-z0-9._-]*|""|.|..|-*)
    echo "run-ladder.sh: exposure id '$EXPOSURE' is not a plain name" >&2
    exit 3
    ;;
esac

FX="$LAB/fixtures"
SRC="$FX/ladder/ladder.c"
RECORDS="$LAB/records/$EXPOSURE"
MANIFEST="$LAB/exposures/$EXPOSURE.kv"

mkdir -p "$LAB/exposures" "$LAB/objects" "$LAB/stderr" "$RECORDS"

# Emptied before anything else happens, refusals included. A manifest with a
# non-zero rc must never sit beside a previous run's twelve records, or the
# grader reads somebody else's exposure as this one's.
rm -f "$RECORDS"/*.json

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1700000000}

# Paths that leave this script are relative or tilde-shortened; the lab lives
# under a home directory whose name is not this repository's business.
sanitise() { sed -e "s#$HOME#~#g" -e "s#$LAB#<lab>#g"; }

LADDER_SHA=absent
GENERATOR_SHA=$(sha256sum "$HERE/../tools/make-ladder.sh" | cut -d' ' -f1)
PLUGIN_SHA=absent
[ -f "$PLUGIN" ] && PLUGIN_SHA=$(sha256sum "$PLUGIN" | cut -d' ' -f1)
# `absent` until the compiler has been found and asked, for the same reason
# LADDER_SHA is: a refusal that fires before the thing exists has to write a word
# into the manifest rather than an empty value. Capturing `$CC --version` here
# unchecked wrote `ccVersion=` whenever $CC did not resolve, and an empty
# ccVersion is the one value build-ladder-frontier.py:638 reads as "this manifest
# makes no claim about the compiler" and skips its manifest-against-records
# comparison over -- so the manifest of a run that never found a compiler read as
# the manifest of a run that got further than it did. `absent` fails that test
# closed instead: no clang version is a substring of it.
CC_VERSION=absent
OBSERVED=0
REFUSAL=

# The manifest is where the raw argv lives, in the shape observe-config.sh
# already uses for it: a record does not carry its own invocation, and an
# exposure reading whose command line is not written down beside it cannot be
# said to be an exposure reading at all. The two shas are what make one run
# comparable with another -- a different specimen or a different generator is
# `exposure-incomparable`, not a mismatch -- and the grader needs them from the
# manifest because a record does not carry them either.
emit_manifest() { # rc
  {
    echo "exposureId=$EXPOSURE"
    echo "opt=$OPT"
    echo "cc=$CC"
    echo "ccVersion=$CC_VERSION"
    echo "rungCount=${#RUNGS[@]}"
    echo "rungsObserved=$OBSERVED"
    # The rung ids in table order, so that a reader can tell twelve records
    # written by this table from twelve records written by a different one
    # without opening them.
    printf 'rungs=%s\n' "$(printf '%s\n' "${RUNGS[@]}" | cut -d'|' -f1 | paste -sd,)"
    echo "records=records/$EXPOSURE"
    echo "ladderSha256=$LADDER_SHA"
    echo "generatorSha256=$GENERATOR_SHA"
    echo "pluginSha256=$PLUGIN_SHA"
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

# The list run-envelope.sh counts a wipe with, unchanged: a spelling the
# envelope treats as the effect and a spelling the ladder treats as the effect
# have to be the same spelling, or the two instruments are answering different
# questions about the same build.
WIPE_SYMS="llvm.memset,memset,explicit_bzero,bzero,__memset_chk,memset_s"

# rung | extractor | subject | control | symbols
#
# Twelve rungs over four subjects. Three of them (b1, d1) are read three times
# against three different controls, because what moves under a fortifying header
# is not whether the effect is there but which spelling carries it: matchesSymbol
# is exact-match or prefix-then-dot, so `memset`, `llvm.memset` and
# `__memset_chk` are three disjoint questions and one rung each is what makes
# the answer readable.
RUNGS=(
  "a0|ir.wipe-effect|vgl_a0|vgl_a1_twin|$WIPE_SYMS"
  "a1|ir.wipe-effect|vgl_a1|vgl_a1_twin|$WIPE_SYMS"
  "a2|ir.wipe-effect|vgl_a2|vgl_a2_twin|$WIPE_SYMS"
  "a3|ir.wipe-effect|vgl_a3|vgl_a3_twin|$WIPE_SYMS"
  "b1-intr|ir.wipe-effect|vgl_b1|vgl_ctl_intr|llvm.memset"
  "b1-lib|ir.wipe-effect|vgl_b1|vgl_ctl_lib|memset"
  "b1-chk|ir.wipe-effect|vgl_b1|vgl_ctl_chk|__memset_chk"
  "c1|ir.guarded-call|vgl_c1|vgl_c1_twin|vgl_deny"
  "c2|ir.guarded-call|vgl_c2|vgl_c1_twin|vgl_deny"
  "d1-printf|ir.forbidden-callee|vgl_d1|vgl_ctl_printf|printf"
  "d1-puts|ir.forbidden-callee|vgl_d1|vgl_ctl_puts|puts"
  "d1-chk|ir.forbidden-callee|vgl_d1|vgl_ctl_printf_chk|__printf_chk"
)

# --- refusals, before anything is compiled -----------------------------------

# An LTO token is refused rather than measured. The plugin registers on the
# pipeline-start and optimizer-last extension points, which the LTO backend
# pipeline does not invoke -- the envelope's own backend cells are declared
# broken for exactly this reason -- so what a -flto compile can be observed
# doing is the prelink stage only. The envelope's `lto` label fuses a build flag
# with an observation stage, so a prelink reading offered as this build's
# exposure would be a false attribution: it would answer for a pipeline nothing
# looked at. Refusing is the honest reading, and it is a 3 because the check
# could not be made, not a 0 because nothing went wrong.
for arg in "$OPT" "${EXTRA[@]+"${EXTRA[@]}"}"; do
  case "$arg" in
    -flto*)
      echo "run-ladder.sh: $EXPOSURE: refusing '$arg': lto-stage-unobserved" >&2
      REFUSAL=lto-stage-unobserved
      finish 3
      ;;
  esac
done

if [ ! -f "$PLUGIN" ]; then
  echo "run-ladder.sh: no plugin at $PLUGIN" >&2
  echo "  cmake -S compiler/llvm-pass -B ~/vg-build/llvm-pass -G Ninja \\" >&2
  echo "        -DLLVM_DIR=\$(llvm-config-18 --cmakedir) && ninja -C ~/vg-build/llvm-pass" >&2
  REFUSAL=plugin-absent
  finish 3
fi

# The compiler is checked by name beside the plugin, before the first rung is
# compiled. Without this an IRCK_CC that does not resolve arrives as the shell's
# own "command not found" on the first compile, rc=127, which the loop below
# reports as exit 1 with the word `toolchain-refused-invocation` -- and a
# toolchain that was never there refused nothing. Not finding the compiler is a
# check that could not be made, so it is 3 under its own word. Same shape as
# second-language-measure.sh:79-84, and for the same reason it says out loud
# there: this is a failure, not a skip.
if ! command -v "$CC" >/dev/null 2>&1; then
  echo "run-ladder.sh: '$CC' (IRCK_CC) does not resolve to a command" >&2
  REFUSAL=compiler-absent
  finish 3
fi

# Asked only once the name is known to resolve, and the answer checked rather
# than assumed. This string is the manifest's whole claim about which compiler
# ran, and it is what build-ladder-frontier.py holds the records' own
# `toolchain.clang` against; an empty one turns that comparison off silently.
CC_VERSION_LINE=$("$CC" --version | head -1)
if [ -z "$CC_VERSION_LINE" ]; then
  echo "run-ladder.sh: '$CC --version' printed nothing, so the manifest cannot name the compiler that ran" >&2
  REFUSAL=compiler-version-unreadable
  finish 3
fi
# Assigned only once it is known to be non-empty, so that the refusal above
# leaves `ccVersion=absent` rather than the `ccVersion=` this check exists to
# keep out of a manifest.
CC_VERSION=$CC_VERSION_LINE

# --- the specimen, and the rung table checked against it ---------------------

LADDER_OUT=$(bash "$HERE/../tools/make-ladder.sh")
rc=$?
if [ $rc -ne 0 ] || [ ! -s "$SRC" ]; then
  echo "run-ladder.sh: $EXPOSURE: make-ladder.sh exited $rc and left no specimen at $SRC" >&2
  REFUSAL=ladder-not-generated
  finish 3
fi
LADDER_SHA=$(sha256sum "$SRC" | cut -d' ' -f1)

# The names the emitted file actually defines, from the generator's own reading
# of its own output. A rung naming a function that is not in this list would not
# fail: the observer would resolve nothing, exit 0, write a record whose control
# held, and leave only the subject's rows empty -- a reading indistinguishable
# at a glance from a property that was never there. Checking the table here is
# what turns that into a refusal.
DEFINED=" $(printf '%s\n' "$LADDER_OUT" | sed -n 's/^fn=//p' | tr '\n' ' ')"
for r in "${RUNGS[@]}"; do
  IFS='|' read -r RUNG EXTRACTOR SUBJ CTL SYMS <<< "$r"
  for fn in "$SUBJ" "$CTL"; do
    case "$DEFINED" in
      *" $fn "*) ;;
      *)
        echo "run-ladder.sh: $EXPOSURE: rung $RUNG names $fn, which the ladder does not define" >&2
        REFUSAL=ladder-function-missing
        finish 3
        ;;
    esac
  done
done

# The compile is run from the specimen's directory and given a relative input,
# so the module identifier in every record is `ladder.c` and not a path through
# somebody's home directory. The module identifier is inside the evidence
# digest, so an absolute path there would make two labs disagree about a digest
# for a reason that has nothing to do with the exposure being read. Every other
# path used below is absolute, and IRCK_CC therefore has to be a command name or
# an absolute path rather than a relative one.
cd "$FX/ladder" || {
  echo "run-ladder.sh: $EXPOSURE: cannot enter $FX/ladder" >&2
  REFUSAL=ladder-not-generated
  finish 3
}

# --- twelve observations ------------------------------------------------------

for r in "${RUNGS[@]}"; do
  IFS='|' read -r RUNG EXTRACTOR SUBJ CTL SYMS <<< "$r"

  RECORD="$RECORDS/$RUNG.json"
  ERRFILE="$LAB/stderr/$EXPOSURE-$RUNG.txt"
  rm -f "$RECORD" "$ERRFILE"

  # Exactly one symbol list is set: ir.forbidden-callee reads
  # OBS_FORBIDDEN_SYMBOLS and the other two read OBS_EFFECT_SYMBOLS. The rest of
  # the observer's knobs are removed rather than left alone, because the reading
  # has to be a function of the command line under test and of nothing else --
  # an OBS_REQUIRE_LIVE_BRANCH exported by whoever called this script would
  # change the guard rungs, and an OBS_SNAPSHOT_DIR would write this run's IR
  # into another run's directory. `env` rather than prefix assignments for the
  # same reason run-envelope.sh uses it: a configuration that leaks from one
  # observation into the next is the bug this component exists to catch
  # elsewhere.
  OBS=(OBS_EXTRACTOR="$EXTRACTOR"
       OBS_PROPERTY_ID="ladder.$RUNG"
       OBS_TARGET_FN="$SUBJ"
       OBS_CONTROL_FN="$CTL"
       OBS_FIXTURE_REL="ladder/ladder.c"
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
      -c ladder.c -o "$LAB/objects/$EXPOSURE-$RUNG.o" 2> "$ERRFILE"
  rc=$?

  # The per-rung file is a copy for a later reader, not the only copy. Printing
  # its name and nothing else made every compile error look alike: interfaces.md
  # section 7 says of exit 1 that the underlying tool's "diagnostics pass through
  # unchanged", and observe.sh:32-38 -- the tree's own precedent -- never takes
  # them off stderr at all. A caller that reads this run's output and cannot
  # reach a path under someone else's lab directory (CI, a pipe, a second
  # machine) was being told that a compile failed and not why.
  if [ $rc -ne 0 ]; then
    echo "run-ladder.sh: $EXPOSURE/$RUNG: compiler exited $rc; its diagnostics follow (copy in stderr/$EXPOSURE-$RUNG.txt)" >&2
    if [ -s "$ERRFILE" ]; then
      cat "$ERRFILE" >&2
    else
      echo "run-ladder.sh: $EXPOSURE/$RUNG: the compiler exited $rc and printed no diagnostic" >&2
    fi
    REFUSAL=toolchain-refused-invocation
    finish 1
  fi
  # The observer's other silent failure: a rejected OBS_* leaves the plugin
  # unregistered, the compiler exits 0 and nothing at all is measured. A wrapper
  # that forwarded that 0 would report an unexamined build as examined.
  #
  # The captured stderr is emitted here too, though the compiler exited 0. The
  # plugin writes its reason for not installing to stderr and lets the compile
  # succeed (IrCheckpoints.cpp:1022, "refusing to install: ..."), so the one line
  # that says which OBS_* was rejected is in the file this rung just filled --
  # and a refusal whose stated cause is sitting in a file the caller was only
  # given the name of is a refusal reported worse than it was diagnosed.
  if [ ! -s "$RECORD" ]; then
    echo "run-ladder.sh: $EXPOSURE/$RUNG: the compile succeeded and no record was written" >&2
    if [ -s "$ERRFILE" ]; then
      echo "run-ladder.sh: $EXPOSURE/$RUNG: what the compiler said (copy in stderr/$EXPOSURE-$RUNG.txt):" >&2
      cat "$ERRFILE" >&2
    fi
    REFUSAL=observer-wrote-no-record
    finish 3
  fi

  OBSERVED=$((OBSERVED + 1))
  printf '%-10s %s\n' "$RUNG" "records/$EXPOSURE/$RUNG.json"
done

echo "$EXPOSURE: $OBSERVED records under ${LAB#"$HOME/"}/records/$EXPOSURE"
# Said out loud because a run that ends here has measured an exposure and
# concluded nothing about it, and the last line of the run is where that is
# easiest to miss.
echo "records only -- no frontier, no comparison, no verdict."
finish 0
