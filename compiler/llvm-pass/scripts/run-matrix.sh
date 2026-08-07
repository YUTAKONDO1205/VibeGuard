#!/bin/bash
# The whole measurement: every cell, including the ones whose job is to fail.
#
# Run from anywhere:
#   bash compiler/llvm-pass/scripts/run-matrix.sh
#
# Reads:   $IRCK_LAB/fixtures (written by tools/make-fixtures.sh)
# Writes:  $IRCK_LAB (default ~/vg-lab/llvm-pass) -- records/, snapshots/, objects/
# Decides: nothing. check-matrix.py does that, so the thing that produces the
#          number is not the thing that grades it.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
LAB=${IRCK_LAB:-$HOME/vg-lab/llvm-pass}
OBS="$HERE/observe.sh"

# The fixtures are written into the lab rather than kept beside this script: a
# measurement input under compiler/ is a boundary violation, and the guard fails
# the build on one. Generating them here also means a run cannot silently use a
# stale or hand-edited copy -- whatever is in tools/make-fixtures.sh is what was
# measured.
bash "$HERE/../tools/make-fixtures.sh" >/dev/null
FX="$LAB/fixtures"

WIPE_SYMS="llvm.memset,memset,explicit_bzero,bzero,__memset_chk,memset_s"

fail=0

# cell VAR=VAL ... -- <cell-id> <fixture-dir> <source> <opt> [clang args...]
#
# The environment goes through `env` rather than as a prefix on a shell function
# call: a prefix assignment in front of a function persists in the calling shell
# in bash, which would leak one cell's configuration into the next -- and the
# cells that exist to be broken are exactly the ones whose configuration must
# not leak.
cell() {
  local envv=()
  while [ "$1" != "--" ]; do envv+=("$1"); shift; done
  shift
  env "${envv[@]}" bash "$OBS" "$@" || fail=1
}

# --- must-survive, secure erasure -------------------------------------------
# The subject's wipe is a dead store; the control's is observable. Four
# optimisation levels, because a property observed to survive -O1 has not been
# observed to survive -O3.
for O in -O0 -O1 -O2 -O3; do
  cell OBS_EXTRACTOR=ir.wipe-effect \
       OBS_PROPERTY_ID=erasure.wipe \
       OBS_TARGET_FN=handle_request \
       OBS_CONTROL_FN=wipe_kept \
       OBS_EFFECT_SYMBOLS="$WIPE_SYMS" \
       OBS_FIXTURE_REL=erasure/target.c \
       -- "erasure${O}" "$FX/erasure" target.c "$O"
done

# --- LOST against NOT_APPLICABLE, from identical source ----------------------
# Same bytes, one -D apart. The effect count goes 1 -> 0 in both.
for O in -O0 -O2; do
  cell OBS_EXTRACTOR=ir.wipe-effect \
       OBS_PROPERTY_ID=promotion.wipe \
       OBS_TARGET_FN=use_token \
       OBS_CONTROL_FN=wipe_out \
       OBS_EFFECT_SYMBOLS="$WIPE_SYMS" \
       OBS_FIXTURE_REL=promotion/token.c \
       -- "promotion-escape-off${O}" "$FX/promotion" token.c "$O"

  cell OBS_EXTRACTOR=ir.wipe-effect \
       OBS_PROPERTY_ID=promotion.wipe \
       OBS_TARGET_FN=use_token \
       OBS_CONTROL_FN=wipe_out \
       OBS_EFFECT_SYMBOLS="$WIPE_SYMS" \
       OBS_FIXTURE_REL=promotion/token.c \
       -- "promotion-escape-on${O}" "$FX/promotion" token.c "$O" -DOBS_FIXTURE_ESCAPE
done

# --- a same-sized bystander must not vouch for the subject ---------------------
for O in -O0 -O2; do
  cell OBS_EXTRACTOR=ir.wipe-effect        OBS_PROPERTY_ID=promotion.wipe        OBS_TARGET_FN=use_token        OBS_CONTROL_FN=wipe_out        OBS_EFFECT_SYMBOLS="$WIPE_SYMS"        OBS_FIXTURE_REL=promotion-decoy/token.c        -- "promotion-decoy${O}" "$FX/promotion-decoy" token.c "$O"
done

# --- NOT_APPLICABLE by the unit disappearing --------------------------------
for O in -O0 -O2; do
  cell OBS_EXTRACTOR=ir.wipe-effect \
       OBS_PROPERTY_ID=inlined.wipe \
       OBS_TARGET_FN=scrub_and_report \
       OBS_CONTROL_FN=wipe_out \
       OBS_EFFECT_SYMBOLS="$WIPE_SYMS" \
       OBS_FIXTURE_REL=inlined/target.c \
       -- "inlined${O}" "$FX/inlined" target.c "$O"
done

# --- the unit disappears AND the effect goes with it ---------------------------
# The pair that separates "the question changed" from "the answer is no". Both
# cells lose the subject unit to the inliner; only one still performs the wipe.
for O in -O0 -O2; do
  cell OBS_EXTRACTOR=ir.wipe-effect        OBS_PROPERTY_ID=inlined.wipe        OBS_TARGET_FN=scrub_and_report        OBS_CONTROL_FN=wipe_out        OBS_EFFECT_SYMBOLS="$WIPE_SYMS"        OBS_FIXTURE_REL=inlined-removable/target.c        -- "inlined-removable${O}" "$FX/inlined-removable" target.c "$O"
done

# --- declaration residue: the naive oracle and the call-site oracle disagree --
for O in -O0 -O2; do
  cell OBS_EXTRACTOR=ir.wipe-effect \
       OBS_PROPERTY_ID=residue.wipe \
       OBS_TARGET_FN=handle_request \
       OBS_CONTROL_FN=wipe_kept \
       OBS_EFFECT_SYMBOLS="$WIPE_SYMS" \
       OBS_FIXTURE_REL=residue/target.c \
       -- "residue${O}" "$FX/residue" target.c "$O"
done

# --- must-survive, fail-closed branch ---------------------------------------
for O in -O0 -O2; do
  cell OBS_EXTRACTOR=ir.guarded-call \
       OBS_PROPERTY_ID=authz.failclosed \
       OBS_TARGET_FN=serve \
       OBS_CONTROL_FN=serve_control \
       OBS_EFFECT_SYMBOLS=deny_and_abort \
       OBS_FIXTURE_REL=authz/target.c \
       -- "authz-live${O}" "$FX/authz" target.c "$O"

  cell OBS_EXTRACTOR=ir.guarded-call \
       OBS_PROPERTY_ID=authz.failclosed \
       OBS_TARGET_FN=serve_folded \
       OBS_CONTROL_FN=serve_control \
       OBS_EFFECT_SYMBOLS=deny_and_abort \
       OBS_FIXTURE_REL=authz/target.c \
       -- "authz-folded${O}" "$FX/authz" target.c "$O"
done

# --- must-not-appear, at the IR checkpoints ---------------------------------
# Not the authoritative checkpoint for this kind -- that is the object, and this
# component does not read objects. properties.json says so rather than letting
# an IR-only reading stand in for one.
for O in -O0 -O2; do
  cell OBS_EXTRACTOR=ir.forbidden-callee \
       OBS_PROPERTY_ID=notappear.deny-path-call \
       OBS_TARGET_FN=serve_folded \
       OBS_CONTROL_FN=serve_control \
       OBS_EFFECT_SYMBOLS=deny_and_abort \
       OBS_FORBIDDEN_SYMBOLS=deny_and_abort \
       OBS_FIXTURE_REL=authz/target.c \
       -- "notappear${O}" "$FX/authz" target.c "$O"
done

# ============================================================================
# Positive controls. Each one breaks something on purpose. A run in which they
# all still look fine has proved the corresponding check is inert.
# ============================================================================

# PC1  Switch off the memory-object discriminator. The cell that reads
#      NOT_APPLICABLE must then read LOST -- otherwise the discriminator is not
#      what produced that verdict.
cell OBS_EXTRACTOR=ir.wipe-effect \
     OBS_PROPERTY_ID=promotion.wipe \
     OBS_TARGET_FN=use_token \
     OBS_CONTROL_FN=wipe_out \
     OBS_EFFECT_SYMBOLS="$WIPE_SYMS" \
     OBS_FIXTURE_REL=promotion/token.c \
     OBS_DISABLE_MEMOBJ_DISCRIMINATOR=1 \
     -- "pc1-no-discriminator-O2" "$FX/promotion" token.c -O2

# PC2  Name a control whose effect the compiler is allowed to delete. The
#      control must be reported as not having held, and the run must not come
#      back clean.
cell OBS_EXTRACTOR=ir.wipe-effect \
     OBS_PROPERTY_ID=erasure.wipe \
     OBS_TARGET_FN=handle_request \
     OBS_CONTROL_FN=wipe_removable_not_a_control \
     OBS_EFFECT_SYMBOLS="$WIPE_SYMS" \
     OBS_FIXTURE_REL=erasure/target.c \
     -- "pc2-broken-control-O2" "$FX/erasure" target.c -O2

# PC3  Point the subject at a function that is not in this translation unit.
#      The result must be NOT_OBSERVED, never ABSENT and never a pass.
cell OBS_EXTRACTOR=ir.wipe-effect \
     OBS_PROPERTY_ID=erasure.wipe \
     OBS_TARGET_FN=no_such_function \
     OBS_CONTROL_FN=wipe_kept \
     OBS_EFFECT_SYMBOLS="$WIPE_SYMS" \
     OBS_FIXTURE_REL=erasure/target.c \
     -- "pc3-missing-subject-O2" "$FX/erasure" target.c -O2

# PC4  Configure the oracle against a symbol nothing calls. The control must be
#      reported as not having held -- an oracle pointed at the wrong symbol must
#      not read as a clean build.
cell OBS_EXTRACTOR=ir.wipe-effect \
     OBS_PROPERTY_ID=erasure.wipe \
     OBS_TARGET_FN=handle_request \
     OBS_CONTROL_FN=wipe_kept \
     OBS_EFFECT_SYMBOLS=no_such_wipe_symbol \
     OBS_FIXTURE_REL=erasure/target.c \
     -- "pc4-wrong-symbol-O2" "$FX/erasure" target.c -O2

exit $fail
