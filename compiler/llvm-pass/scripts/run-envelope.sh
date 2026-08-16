#!/bin/bash
# The security configuration envelope: every cell, across the axes a build
# actually varies, including the cells whose job is to fail.
#
# Run from anywhere:
#   bash compiler/llvm-pass/scripts/run-envelope.sh
#
# Reads:   $IRCK_ENV_LAB/fixtures (written here by make-fixtures.sh and
#          envelope-fixtures.sh)
# Writes:  $IRCK_ENV_LAB (default ~/vg-lab/llvm-pass-envelope)
# Decides: nothing. build-envelope.py assembles the envelope and
#          check-envelope.py grades it, so the thing that produces the number is
#          not the thing that grades it.
#
# Why a second lab rather than more cells in run-matrix.sh: the optimisation
# matrix is a graded artefact with a published expectation for every cell, and a
# sweep that writes into its records directory can only make that grade less
# trustworthy. Nothing here can touch it.
#
# The axes:
#
#   opt           -O0 -O1 -O2 -O3      already in the matrix
#   ndebug        off | on             a -D, not an optimisation level
#   lto           none | full-prelink | thin-prelink | full-backend | thin-backend
#   target        host | arm-none-eabi | aarch64-none-elf
#   freestanding  off | on             see the note on the confound below
#
# freestanding is an axis rather than a fixed flag because it is a confound for
# the target axis. -ffreestanding stops the compiler treating memset as a
# builtin, which alone changes the erasure verdict on an unchanged target -- so a
# cross-target cell that carried -ffreestanding while its host counterpart did
# not would attribute a flag's effect to a processor. The sweep therefore holds
# freestanding fixed within the target comparison and varies it separately, and
# check-envelope.py refuses a target claim drawn across cells that differ in it.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
LAB=${IRCK_ENV_LAB:-$HOME/vg-lab/llvm-pass-envelope}
export IRCK_LAB="$LAB"

bash "$HERE/../tools/make-fixtures.sh" >/dev/null
bash "$HERE/envelope-fixtures.sh" >/dev/null
FX="$LAB/fixtures"

WIPE_SYMS="llvm.memset,memset,explicit_bzero,bzero,__memset_chk,memset_s"

fail=0

# subject <name> -- fills the OBS_* description of one property under test.
# Kept as a function returning an env list, for the same reason run-matrix.sh
# routes its environment through `env`: a prefix assignment in front of a shell
# function persists in the caller, and a configuration that leaks from one cell
# into the next is exactly the bug this component exists to catch elsewhere.
subject_env() {
  case "$1" in
    erasure)
      echo "OBS_EXTRACTOR=ir.wipe-effect OBS_PROPERTY_ID=erasure.wipe
            OBS_TARGET_FN=handle_request OBS_CONTROL_FN=wipe_kept
            OBS_EFFECT_SYMBOLS=$WIPE_SYMS OBS_FIXTURE_REL=erasure/target.c" ;;
    authz-live)
      echo "OBS_EXTRACTOR=ir.guarded-call OBS_PROPERTY_ID=authz.failclosed
            OBS_TARGET_FN=serve OBS_CONTROL_FN=serve_control
            OBS_EFFECT_SYMBOLS=deny_and_abort OBS_FIXTURE_REL=authz/target.c" ;;
    authz-folded)
      echo "OBS_EXTRACTOR=ir.guarded-call OBS_PROPERTY_ID=authz.failclosed
            OBS_TARGET_FN=serve_folded OBS_CONTROL_FN=serve_control
            OBS_EFFECT_SYMBOLS=deny_and_abort OBS_FIXTURE_REL=authz/target.c" ;;
    ndebug-guard)
      echo "OBS_EXTRACTOR=ir.guarded-call OBS_PROPERTY_ID=ndebug.failclosed
            OBS_TARGET_FN=serve_asserted OBS_CONTROL_FN=serve_control
            OBS_EFFECT_SYMBOLS=deny_and_abort OBS_FIXTURE_REL=ndebug/target.c" ;;
    *) echo "run-envelope.sh: unknown subject $1" >&2; exit 1 ;;
  esac
}

subject_dir() {
  case "$1" in
    erasure) echo "erasure target.c" ;;
    authz-live|authz-folded) echo "authz target.c" ;;
    ndebug-guard) echo "ndebug target.c" ;;
  esac
}

# cell <subject> <opt> <ndebug> <lto> <target> <freestanding> <tag> [extra env ...]
#
# <tag> is "-" for an ordinary cell. A positive control shares its configuration
# with an ordinary cell on purpose -- that is what makes it a control -- so it
# needs a name of its own or it would overwrite the cell it is supposed to be
# compared against.
cell() {
  local subj=$1 opt=$2 nd=$3 lto=$4 tgt=$5 fs=$6 tag=$7
  shift 7
  local dir src
  read -r dir src <<<"$(subject_dir "$subj")"
  local id="$subj+opt=${opt#-}+ndebug=$nd+lto=$lto+target=$tgt+free=$fs"
  [ "$tag" != "-" ] && id="$id+ctl=$tag"
  # The subject description is a whitespace-separated list of KEY=VALUE, and it
  # is split into an array rather than left to the word splitting of an unquoted
  # $(...). Both work; the array says so out loud, keeps `set -u` honest, and
  # needs no linter directive to sit above it -- and the directive is what made
  # this line a finding for scripts/sweep-disclosure.mjs, whose acronym-and-year
  # shape cannot tell a shellcheck code from a venue name. Removing the need for
  # the directive is cheaper than teaching the disclosure guard an exemption,
  # and an exemption is the thing you cannot take back once a real one hides in it.
  # The descriptions are written across several lines for readability, and
  # `read -a` stops at the first newline -- so the newlines are folded to spaces
  # before the split. Without the fold this silently passes only the first line's
  # variables, which does not fail: it produces cells that ran with half an
  # observer configuration and recorded whatever that measured.
  local -a senv
  read -r -a senv <<<"$(subject_env "$subj" | tr '\n' ' ')"
  env CELL_SUBJECT="$subj" "${senv[@]}" "$@" \
      bash "$HERE/observe-config.sh" "$id" "$FX/$dir" "$src" "$opt" "$nd" "$lto" "$tgt" "$fs"
  local rc=$?
  printf '%-72s rc=%d\n' "$id" "$rc"
  # A non-zero here is a cell-level outcome, not a run-level one: an unsupported
  # target and a broken observation are both results this sweep is meant to
  # record. build-envelope.py turns them into labelled cells and
  # check-envelope.py decides whether that outcome was the declared one.
  return 0
}

echo "=== base sweep: optimisation x NDEBUG, native, no LTO ==="
for subj in erasure authz-live authz-folded ndebug-guard; do
  for O in -O0 -O1 -O2 -O3; do
    for ND in 0 1; do
      cell "$subj" "$O" "$ND" none host 0 -
    done
  done
done

echo
echo "=== LTO sweep: pre-link and backend ==="
for subj in erasure authz-folded ndebug-guard; do
  for O in -O0 -O2; do
    for L in full-prelink thin-prelink; do
      cell "$subj" "$O" 0 "$L" host 0 -
    done
    # The backend cells are declared broken in advance, with the reason, because
    # the observer's two checkpoints are extension points the LTO backend
    # pipeline does not invoke. Declaring it makes the claim falsifiable:
    # check-envelope.py fails the run if one of these ever succeeds, which is
    # what would happen the day the plugin registers its checkpoints somewhere
    # the backend reaches.
    for L in full-backend thin-backend; do
      cell "$subj" "$O" 0 "$L" host 0 - \
           CELL_EXPECTED_BROKEN=1 \
           CELL_EXPECTED_BROKEN_REASON="observer-not-reached-in-lto-backend"
    done
  done
done

echo
echo "=== target sweep: freestanding held fixed at off ==="
for subj in erasure authz-folded ndebug-guard; do
  for O in -O0 -O2; do
    cell "$subj" "$O" 0 none arm-none-eabi 0 -
    # aarch64-none-elf has no sysroot here, so how far it gets depends on the
    # fixture rather than on the triple: erasure includes <string.h> and cannot
    # be preprocessed without a libc, while the others declare every external by
    # hand and compile with nothing but the compiler. The declaration is per
    # fixture for that reason, and the first version of this file got it wrong in
    # the safe-looking direction -- it declared all three broken, and the two
    # that work were being hidden by the declaration until check-envelope.py
    # refused it.
    if [ "$subj" = "erasure" ]; then
      cell "$subj" "$O" 0 none aarch64-none-elf 0 - \
           CELL_EXPECTED_BROKEN=1 \
           CELL_EXPECTED_BROKEN_REASON="no-libc-headers-for-triple"
    else
      cell "$subj" "$O" 0 none aarch64-none-elf 0 -
    fi
  done
done

echo
echo "=== freestanding sweep: the confound, held on its own axis ==="
for O in -O0 -O2; do
  cell erasure "$O" 0 none host 1 -
  cell erasure "$O" 0 none arm-none-eabi 1 -
done

echo
echo "=== positive controls for the envelope's own failure modes ==="
# PCE1  No plugin at the configured path. The toolchain must refuse, the cell
#       must read UNSUPPORTED, and the run must not come back clean.
cell erasure -O2 0 none host 0 pce1-plugin-absent \
     IRCK_PLUGIN=/nonexistent/libIrCheckpoints.so \
     CELL_EXPECTED_BROKEN=1 CELL_EXPECTED_BROKEN_REASON="plugin-absent"
# PCE2  The plugin is there and one required OBS_* is not, which is the observer's
#       silent failure mode: the plugin registers nothing, the compiler exits 0,
#       and no record is written. A cell that reported that as clean would be
#       reporting an unexamined build as examined. It must read
#       BROKEN_MEASUREMENT.
cell erasure -O2 0 none host 0 pce2-observer-unregistered \
     OBS_TARGET_FN= \
     CELL_EXPECTED_BROKEN=1 CELL_EXPECTED_BROKEN_REASON="observer-unregistered"

echo
echo "cells written to ${LAB#"$HOME/"}/cells"
exit $fail
