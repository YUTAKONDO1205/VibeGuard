#!/bin/bash
# One configuration, every metamorphic cell: each (base, mutant) pair compiled
# under one command line, through the real observer, and through the assembly
# oracle on both vendors for the cells the catalogue marks crossVendor.
#
#   bash compiler/eval/metamorphic/scripts/run-metamorphic.sh <run-id> <opt> [extra args...]
#
#   bash .../run-metamorphic.sh O0 -O0
#   bash .../run-metamorphic.sh O2 -O2
#
# Reads:   the catalogue (tracked) and the specimens tools/make-mutants.py emits
#          into $VG_META_LAB (default ~/vg-lab/metamorphic)
# Writes:  $VG_META_LAB/records/<run-id>/{ir,asm}/*.json and one manifest
# Decides: NOTHING. It leaves two records per cell, one asm reading per cell per
#          vendor, and a manifest. Whether a cell moved along its declared edge,
#          whether an R1 relation held, and whether the two vendors made the same
#          difference are all read out of those records by other files --
#          build-meta-report.py assembles and check-meta.py grades. The same split
#          as run-ladder.sh / build-ladder-frontier.py / check-ladder.py, for the
#          same reason: a component that decides whether its own reading is good
#          is not a measurement.
#
# In particular nothing here compares a base against its mutant. Two records
# sitting in one directory are not a transition until something reads them, and
# keeping the comparison out of the producer is what stops a reading being tuned
# to the answer it is about to be asked for.
#
# THE OBSERVER'S THREE SILENT FAILURE MODES, ALL THREE FENCED HERE
#
# This harness inherits no fence from the ladder, so it builds its own, and the
# three are separate because each fails in a way the other two do not.
#
#  (a) the toolchain refuses the invocation. rc is non-zero. The diagnostics pass
#      through to stderr UNCHANGED, as interfaces.md section 7 requires of an exit
#      1, and the run stops.
#  (b) a rejected OBS_* leaves the plugin uninstalled. THE COMPILER EXITS 0 AND
#      NOTHING AT ALL IS MEASURED -- the plugin writes "refusing to install: ..."
#      to stderr and lets the compile succeed. So every compile is followed by an
#      assertion that a non-empty record exists, and when it does not the captured
#      stderr is printed rather than merely pointed at, because a refusal whose
#      stated cause sits in a file the caller was only given the name of is a
#      refusal reported worse than it was diagnosed. Exit 3.
#  (c) a subject name that resolves to nothing gives rc 0, an EMPTY stderr, a
#      non-empty log, a HELD control, and only the subject's rows missing --
#      indistinguishable at a glance from a property that was never there. So
#      every subject and control in the cell table is checked against the function
#      list make-mutants.py DERIVED FROM THE EMITTED BYTES, before the first
#      compile. A list kept by hand beside a file can be right about a file that
#      has changed. Exit 3.
#
# An LTO token is refused rather than measured, under the word
# lto-stage-unobserved. The plugin registers on the pipeline-start and
# optimizer-last extension points, which the LTO backend pipeline never invokes,
# so what an -flto compile can be observed doing is the prelink stage only, and
# offering that as this build's exposure would answer for a pipeline nothing
# looked at. It is exit 3 -- the check could not be made -- and never exit 0.
#
# DRIFT PINNING
#
# The generator prints its own sha-256 and the catalogue's; this script recomputes
# both and refuses under generator-digest-moved / catalogue-digest-moved if either
# has changed between the generator reading itself and this script reading it. And
# every emitted specimen's sha-256 goes into the manifest, so that an identical
# generator producing different bytes -- CRLF is the live risk on this checkout --
# is caught rather than absorbed.
#
# Exit codes follow interfaces.md section 7:
#   0  every cell in the table left two records, and every asm reading the lane
#      declared was written
#   1  the toolchain refused an invocation; its diagnostics are on stderr unchanged
#   3  the run could not be made, or was made and left no record
# "Could not look" is never a pass, so every refusal below leaves 3 and never 0,
# and the reason word goes into the manifest as well as onto stderr.
#
# A cell that fails stops the run rather than being skipped: a partial table is
# not a lane, and a caller that received 0 with a cell missing would be reading an
# R1 invariance over a set nobody was told had shrunk.
set -u

RUN=${1:?run id}
OPT=${2:?opt level}
shift 2
EXTRA=("$@")

HERE=$(cd "$(dirname "$0")" && pwd)
LAB=${VG_META_LAB:-$HOME/vg-lab/metamorphic}
PLUGIN=${VG_META_PLUGIN:-$HOME/vg-build/llvm-pass/libIrCheckpoints.so}
CC=${VG_META_CC:-clang-18}
CC2=${VG_META_CC2:-gcc-13}
GENERATOR="$HERE/../tools/make-mutants.py"
CATALOGUE="$HERE/../catalogue.json"
ASM_READ="$HERE/../lib/asm-read.mjs"
NODE=${VG_META_NODE:-node}

# The run id names a directory and a manifest file, so it is checked before it is
# used as one rather than after.
case "$RUN" in
  *[!A-Za-z0-9._-]*|""|.|..|-*)
    echo "run-metamorphic.sh: run id '$RUN' is not a plain name" >&2
    exit 3
    ;;
esac

# Only the basename is recorded. VG_META_CC may be an absolute path, and
# interfaces.md section 5 forbids one anywhere in a digested document; recording
# the basename keeps the document clean by construction instead of leaving the
# assembler to refuse a manifest it was handed.
CC_ID=$(basename "$CC")
CC2_ID=$(basename "$CC2")

SPECIMENS="$LAB/specimens"
RECORDS="$LAB/records/$RUN"
ASMDIR="$LAB/asm/$RUN"
MANIFEST="$LAB/runs/$RUN.kv"

mkdir -p "$LAB/runs" "$LAB/objects/$RUN" "$LAB/stderr/$RUN" \
         "$RECORDS/ir" "$RECORDS/asm" "$ASMDIR"

# Emptied before anything else happens, refusals included. A manifest with a
# non-zero rc must never sit beside a previous run's records, or the assembler
# reads somebody else's run as this one's.
rm -f "$RECORDS/ir"/*.json "$RECORDS/asm"/*.json

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1700000000}

CC_VERSION=absent
CC2_VERSION=absent
PLUGIN_SHA=absent
GENERATOR_SHA=absent
CATALOGUE_SHA=absent
GENERATOR_VERSION=0
OBSERVED=0
ASM_OBSERVED=0
ASM_LANE=NOT_RUN
ASM_LANE_REASON="the run did not reach the asm lane"
REFUSAL=
CELL_COUNT=0
declare -a CELLS=()
declare -a SPECLINES=()

sanitise() { sed -e "s#$HOME#~#g" -e "s#$LAB#<lab>#g"; }

emit_manifest() { # rc
  {
    echo "runId=$RUN"
    echo "opt=$OPT"
    echo "cc=$CC_ID"
    echo "ccVersion=$CC_VERSION"
    echo "cc2=$CC2_ID"
    echo "cc2Version=$CC2_VERSION"
    echo "generatorVersion=$GENERATOR_VERSION"
    echo "generatorSha256=$GENERATOR_SHA"
    echo "catalogueSha256=$CATALOGUE_SHA"
    echo "pluginSha256=$PLUGIN_SHA"
    echo "sourceDateEpoch=$SOURCE_DATE_EPOCH"
    echo "cellCount=$CELL_COUNT"
    echo "cellsObserved=$OBSERVED"
    echo "asmLane=$ASM_LANE"
    echo "asmLaneReason=$ASM_LANE_REASON"
    echo "asmReadingsObserved=$ASM_OBSERVED"
    echo "irRecords=records/$RUN/ir"
    echo "asmReadings=records/$RUN/asm"
    # The operator ids in table order, so a reader can tell records written by
    # this catalogue from records written by a different one without opening them.
    if [ ${#CELLS[@]} -gt 0 ]; then
      printf 'cells=%s\n' "$(printf '%s\n' "${CELLS[@]}" | cut -d'|' -f1 | paste -sd,)"
      printf 'cellSpec=%s\n' "${CELLS[@]}"
    else
      echo "cells="
    fi
    if [ ${#SPECLINES[@]} -gt 0 ]; then
      printf 'specimen=%s\n' "${SPECLINES[@]}"
    fi
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

for arg in "$OPT" "${EXTRA[@]+"${EXTRA[@]}"}"; do
  case "$arg" in
    -flto*)
      echo "run-metamorphic.sh: $RUN: refusing '$arg': lto-stage-unobserved" >&2
      REFUSAL=lto-stage-unobserved
      finish 3
      ;;
  esac
done

if [ ! -f "$PLUGIN" ]; then
  echo "run-metamorphic.sh: no plugin at $PLUGIN" >&2
  echo "  cmake -S compiler/llvm-pass -B ~/vg-build/llvm-pass -G Ninja \\" >&2
  echo "        -DLLVM_DIR=\$(llvm-config-18 --cmakedir) && ninja -C ~/vg-build/llvm-pass" >&2
  REFUSAL=plugin-absent
  finish 3
fi
PLUGIN_SHA=$(sha256sum "$PLUGIN" | cut -d' ' -f1)

# The compiler is checked by name before the first cell is compiled. Without this
# a VG_META_CC that does not resolve arrives as the shell's own "command not
# found", rc=127, which the loop below would report as exit 1 under the word
# toolchain-refused-invocation -- and a toolchain that was never there refused
# nothing. Not finding the compiler is a check that could not be made, so it is 3
# under its own word.
if ! command -v "$CC" >/dev/null 2>&1; then
  echo "run-metamorphic.sh: '$CC' (VG_META_CC) does not resolve to a command" >&2
  REFUSAL=compiler-absent
  finish 3
fi
CC_VERSION_LINE=$("$CC" --version | head -1)
if [ -z "$CC_VERSION_LINE" ]; then
  echo "run-metamorphic.sh: '$CC --version' printed nothing, so the manifest cannot name the compiler that ran" >&2
  REFUSAL=compiler-version-unreadable
  finish 3
fi
CC_VERSION=$CC_VERSION_LINE

# --- the specimens, and the cell table checked against them ------------------

GEN_OUT=$(python3 "$GENERATOR")
rc=$?
if [ $rc -ne 0 ]; then
  echo "run-metamorphic.sh: $RUN: make-mutants.py exited $rc and the specimen set is not measurable" >&2
  REFUSAL=specimens-not-generated
  finish 3
fi

GENERATOR_SHA_CLAIMED=$(printf '%s\n' "$GEN_OUT" | sed -n 's/^generatorSha256=//p' | head -1)
CATALOGUE_SHA_CLAIMED=$(printf '%s\n' "$GEN_OUT" | sed -n 's/^catalogueSha256=//p' | head -1)
GENERATOR_VERSION=$(printf '%s\n' "$GEN_OUT" | sed -n 's/^generatorVersion=//p' | head -1)
GENERATOR_SHA=$(sha256sum "$GENERATOR" | cut -d' ' -f1)
CATALOGUE_SHA=$(sha256sum "$CATALOGUE" | cut -d' ' -f1)

# Recomputed here rather than trusted from the generator's own output. The two
# readings are of the same bytes by two processes; a disagreement means the file
# changed between them, or one side read it through a transformation the other did
# not -- which on this checkout means CRLF. Either way the specimens on disk are
# not the specimens this run can claim to have measured.
if [ "$GENERATOR_SHA" != "$GENERATOR_SHA_CLAIMED" ]; then
  echo "run-metamorphic.sh: $RUN: the generator says its sha256 is $GENERATOR_SHA_CLAIMED and this script recomputes $GENERATOR_SHA" >&2
  REFUSAL=generator-digest-moved
  finish 3
fi
if [ "$CATALOGUE_SHA" != "$CATALOGUE_SHA_CLAIMED" ]; then
  echo "run-metamorphic.sh: $RUN: the generator says the catalogue's sha256 is $CATALOGUE_SHA_CLAIMED and this script recomputes $CATALOGUE_SHA" >&2
  REFUSAL=catalogue-digest-moved
  finish 3
fi
case "$GENERATOR_VERSION" in
  ""|*[!0-9]*)
    echo "run-metamorphic.sh: $RUN: generatorVersion=$GENERATOR_VERSION is not an integer" >&2
    REFUSAL=generator-version-unreadable
    finish 3
    ;;
esac

mapfile -t SPECLINES < <(printf '%s\n' "$GEN_OUT" | sed -n 's/^specimen=//p')
mapfile -t CELLS < <(printf '%s\n' "$GEN_OUT" | sed -n 's/^cell=//p')
CELL_COUNT=${#CELLS[@]}

if [ "$CELL_COUNT" -eq 0 ]; then
  echo "run-metamorphic.sh: $RUN: the generator declared no cells; there is nothing to measure" >&2
  REFUSAL=no-cells-declared
  finish 3
fi
if [ ${#SPECLINES[@]} -eq 0 ]; then
  echo "run-metamorphic.sh: $RUN: the generator declared no specimens" >&2
  REFUSAL=no-specimens-declared
  finish 3
fi

# specimenId -> relative path, and the derived function list per specimen. The
# `fn=` lines are the generator's own reading of its own OUTPUT BYTES; this is the
# fence for silent failure mode (c).
declare -A SPEC_REL=()
declare -A SPEC_SHA=()
for line in "${SPECLINES[@]}"; do
  IFS='|' read -r sid rel sha <<< "$line"
  SPEC_REL[$sid]=$rel
  SPEC_SHA[$sid]=$sha
done
declare -A DEFINED=()
while IFS= read -r line; do
  IFS='|' read -r sid name <<< "$line"
  DEFINED[$sid]="${DEFINED[$sid]:-} $name "
done < <(printf '%s\n' "$GEN_OUT" | sed -n 's/^fn=//p')

for c in "${CELLS[@]}"; do
  IFS='|' read -r OP EXTRACTOR BSPEC MSPEC BSUBJ MSUBJ CTL SYMS XV ASMSYMS ASMIZ <<< "$c"
  for spec in "$BSPEC" "$MSPEC"; do
    if [ -z "${SPEC_REL[$spec]:-}" ]; then
      echo "run-metamorphic.sh: $RUN: cell $OP names specimen $spec, which was not emitted" >&2
      REFUSAL=specimen-missing
      finish 3
    fi
    if [ ! -s "$LAB/${SPEC_REL[$spec]}" ]; then
      echo "run-metamorphic.sh: $RUN: specimen $spec is empty or absent at ${SPEC_REL[$spec]}" >&2
      REFUSAL=specimen-missing
      finish 3
    fi
  done
  for pair in "$BSPEC|$BSUBJ" "$BSPEC|$CTL" "$MSPEC|$MSUBJ" "$MSPEC|$CTL"; do
    IFS='|' read -r spec fn <<< "$pair"
    case "${DEFINED[$spec]:-}" in
      *" $fn "*) ;;
      *)
        echo "run-metamorphic.sh: $RUN: cell $OP names $fn in $spec, which the emitted bytes do not define" >&2
        REFUSAL=specimen-function-missing
        finish 3
        ;;
    esac
  done
done

# The compiles are run from the LAB ROOT and given the same lab-relative path the
# generator declared, so the module identifier in every record is
# `specimens/<shape>/<name>.c` and not a path through somebody's home directory.
# The module identifier is inside the evidence digest, so an absolute path there
# would make two labs disagree about a digest for a reason that has nothing to do
# with the specimen being read -- and one spelling of the path, the generator's,
# is what makes the manifest's `specimen=` lines and the records' `module` agree.
# Every other path below is absolute, and VG_META_CC therefore has to be a command
# name or an absolute path rather than a relative one.
if [ ! -d "$SPECIMENS" ]; then
  echo "run-metamorphic.sh: $RUN: no specimen directory at $SPECIMENS" >&2
  REFUSAL=specimens-not-generated
  finish 3
fi
cd "$LAB" || {
  echo "run-metamorphic.sh: $RUN: cannot enter $LAB" >&2
  REFUSAL=specimens-not-generated
  finish 3
}

# --- the IR channel: two observations per cell -------------------------------

observe() { # operatorId side specimenId subjectFn controlFn extractor symbols
  local op=$1 side=$2 spec=$3 subj=$4 ctl=$5 extractor=$6 syms=$7
  local rel=${SPEC_REL[$spec]}
  local record="$RECORDS/ir/$op.$side.json"
  local errfile="$LAB/stderr/$RUN/$op.$side.txt"
  rm -f "$record" "$errfile"

  # Exactly one symbol list is set: ir.forbidden-callee reads
  # OBS_FORBIDDEN_SYMBOLS and the other two read OBS_EFFECT_SYMBOLS. The rest of
  # the observer's knobs are REMOVED rather than left alone, because the reading
  # has to be a function of the specimen and the command line and of nothing else
  # -- an OBS_REQUIRE_LIVE_BRANCH exported by whoever called this script would
  # change every guarded cell, and an OBS_SNAPSHOT_DIR would write this run's IR
  # into another run's directory. `env` rather than prefix assignments, for the
  # same reason run-ladder.sh uses it: a configuration that leaks from one
  # observation into the next is the bug this component exists to catch elsewhere.
  local -a OBS=(OBS_EXTRACTOR="$extractor"
                OBS_PROPERTY_ID="metamorphic.$op.$side"
                OBS_TARGET_FN="$subj"
                OBS_CONTROL_FN="$ctl"
                OBS_FIXTURE_REL="$rel"
                OBS_OUT="$record")
  if [ "$extractor" = "ir.forbidden-callee" ]; then
    OBS+=(OBS_FORBIDDEN_SYMBOLS="$syms")
  else
    OBS+=(OBS_EFFECT_SYMBOLS="$syms")
  fi

  env -u OBS_EFFECT_SYMBOLS -u OBS_FORBIDDEN_SYMBOLS -u OBS_SNAPSHOT_DIR \
      -u OBS_REQUIRE_LIVE_BRANCH -u OBS_DISABLE_MEMOBJ_DISCRIMINATOR \
      -u OBS_ANNOTATION_PREFIX \
      "${OBS[@]}" \
      "$CC" "$OPT" "${EXTRA[@]+"${EXTRA[@]}"}" -fpass-plugin="$PLUGIN" \
      -c "$rel" -o "$LAB/objects/$RUN/$op.$side.o" 2> "$errfile"
  local rc=$?

  # Silent failure mode (a).
  if [ $rc -ne 0 ]; then
    echo "run-metamorphic.sh: $RUN/$op.$side: compiler exited $rc; its diagnostics follow (copy in stderr/$RUN/$op.$side.txt)" >&2
    if [ -s "$errfile" ]; then
      cat "$errfile" >&2
    else
      echo "run-metamorphic.sh: $RUN/$op.$side: the compiler exited $rc and printed no diagnostic" >&2
    fi
    REFUSAL=toolchain-refused-invocation
    finish 1
  fi
  # Silent failure mode (b).
  if [ ! -s "$record" ]; then
    echo "run-metamorphic.sh: $RUN/$op.$side: the compile succeeded and no record was written" >&2
    if [ -s "$errfile" ]; then
      echo "run-metamorphic.sh: $RUN/$op.$side: what the compiler said (copy in stderr/$RUN/$op.$side.txt):" >&2
      cat "$errfile" >&2
    fi
    REFUSAL=observer-wrote-no-record
    finish 3
  fi
}

for c in "${CELLS[@]}"; do
  IFS='|' read -r OP EXTRACTOR BSPEC MSPEC BSUBJ MSUBJ CTL SYMS XV ASMSYMS ASMIZ <<< "$c"
  observe "$OP" base   "$BSPEC" "$BSUBJ" "$CTL" "$EXTRACTOR" "$SYMS"
  observe "$OP" mutant "$MSPEC" "$MSUBJ" "$CTL" "$EXTRACTOR" "$SYMS"
  OBSERVED=$((OBSERVED + 1))
  printf '%-18s ir  base+mutant  records/%s/ir/%s.{base,mutant}.json\n' "$OP" "$RUN" "$OP"
done

# --- the cross-vendor channel: a DIFFERENT and COARSER instrument ------------
#
# The IR extractors are clang-only by construction, so this channel does not use
# them. It compiles each specimen to assembly with each vendor and reads it with
# compiler/eval/second-vendor/lib/asm-oracle.mjs, which has no per-vendor branch
# anywhere in it. The readings have no pass attribution and cannot tell LOST from
# NOT_APPLICABLE; that is stated in every reading and again in the report.

declare -a XCELLS=()
for c in "${CELLS[@]}"; do
  IFS='|' read -r OP EXTRACTOR BSPEC MSPEC BSUBJ MSUBJ CTL SYMS XV ASMSYMS ASMIZ <<< "$c"
  [ "$XV" = "1" ] && XCELLS+=("$c")
done

if [ ${#XCELLS[@]} -eq 0 ]; then
  ASM_LANE=NOT_DECLARED
  ASM_LANE_REASON="no cell in this catalogue is marked crossVendor"
elif ! command -v "$CC2" >/dev/null 2>&1; then
  # A declared absence rather than silence, and rather than a refusal that would
  # also throw away the IR channel this run did complete. The assembler puts
  # UNSUPPORTED on the lane and the grader reads a lane-level status; what must
  # never happen is a report that simply has no cross-vendor section and exits 0.
  ASM_LANE=UNSUPPORTED
  ASM_LANE_REASON="the second vendor '$CC2_ID' does not resolve to a command on this host, so the comparison could not be attempted"
  echo "run-metamorphic.sh: $RUN: '$CC2' does not resolve; the cross-vendor lane is UNSUPPORTED in this run" >&2
elif ! command -v "$NODE" >/dev/null 2>&1; then
  ASM_LANE=UNSUPPORTED
  ASM_LANE_REASON="node does not resolve to a command on this host, so the assembly oracle could not be run"
  echo "run-metamorphic.sh: $RUN: '$NODE' does not resolve; the cross-vendor lane is UNSUPPORTED in this run" >&2
else
  CC2_VERSION_LINE=$("$CC2" --version | head -1)
  CC2_VERSION=${CC2_VERSION_LINE:-absent}
  ASM_LANE=OK
  ASM_LANE_REASON="both drivers resolved and every declared reading was written"

  # Each specimen is compiled once per vendor, not once per cell: several cells
  # share the base specimen, and compiling it repeatedly would be several chances
  # for two readings of one listing to disagree.
  declare -A ASM_DONE=()
  for vendor_driver in "$CC:$CC_ID" "$CC2:$CC2_ID"; do
    driver=${vendor_driver%%:*}
    vid=${vendor_driver##*:}
    mkdir -p "$ASMDIR/$vid"
    for c in "${XCELLS[@]}"; do
      IFS='|' read -r OP EXTRACTOR BSPEC MSPEC BSUBJ MSUBJ CTL SYMS XV ASMSYMS ASMIZ <<< "$c"
      for spec in "$BSPEC" "$MSPEC"; do
        key="$vid/$spec"
        [ -n "${ASM_DONE[$key]:-}" ] && continue
        ASM_DONE[$key]=1
        rel=${SPEC_REL[$spec]}
        out="$ASMDIR/$vid/$spec.s"
        errfile="$LAB/stderr/$RUN/asm-$vid-$spec.txt"
        "$driver" "$OPT" "${EXTRA[@]+"${EXTRA[@]}"}" -S -o "$out" "$rel" 2> "$errfile"
        rc=$?
        if [ $rc -ne 0 ]; then
          echo "run-metamorphic.sh: $RUN: $vid refused '$OPT' on $spec (rc $rc); its diagnostics follow" >&2
          [ -s "$errfile" ] && cat "$errfile" >&2
          REFUSAL=toolchain-refused-invocation
          finish 1
        fi
        # rc=0 beside an absent output has been observed in this project from a
        # compiler driver, so the artefact is stat'ed rather than inferred.
        if [ ! -s "$out" ]; then
          echo "run-metamorphic.sh: $RUN: $vid exited 0 and wrote no assembly for $spec" >&2
          REFUSAL=asm-not-produced
          finish 3
        fi
      done
    done
  done

  for vendor_driver in "$CC:$CC_ID" "$CC2:$CC2_ID"; do
    vid=${vendor_driver##*:}
    for c in "${XCELLS[@]}"; do
      IFS='|' read -r OP EXTRACTOR BSPEC MSPEC BSUBJ MSUBJ CTL SYMS XV ASMSYMS ASMIZ <<< "$c"
      for side in base mutant; do
        if [ "$side" = base ]; then spec=$BSPEC; subj=$BSUBJ; else spec=$MSPEC; subj=$MSUBJ; fi
        reading="$RECORDS/asm/$OP.$vid.$side.json"
        izflag=()
        [ "$ASMIZ" = "1" ] && izflag=(--inline-zero)
        "$NODE" "$ASM_READ" --asm "$ASMDIR/$vid/$spec.s" \
            --subject "$subj" --control "$CTL" --symbols "$ASMSYMS" \
            "${izflag[@]+"${izflag[@]}"}" --out "$reading" >/dev/null
        rc=$?
        if [ $rc -ne 0 ]; then
          echo "run-metamorphic.sh: $RUN: the assembly oracle exited $rc on $OP/$vid/$side" >&2
          REFUSAL=asm-reading-not-written
          finish 3
        fi
        if [ ! -s "$reading" ]; then
          echo "run-metamorphic.sh: $RUN: the assembly oracle exited 0 and wrote no reading for $OP/$vid/$side" >&2
          REFUSAL=asm-reading-not-written
          finish 3
        fi
        ASM_OBSERVED=$((ASM_OBSERVED + 1))
      done
    done
    printf '%-18s asm %s  %d cell(s)\n' "(cross-vendor)" "$vid" "${#XCELLS[@]}"
  done
fi

echo "$RUN: $OBSERVED cell(s) x 2 IR records, $ASM_OBSERVED asm reading(s), under ${LAB#"$HOME/"}/records/$RUN"
# Said out loud because a run that ends here has measured a configuration and
# concluded nothing about it, and the last line of the run is where that is
# easiest to miss.
echo "records only -- no transition, no agreement, no grade."
finish 0
