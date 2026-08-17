#!/bin/bash
# Write the calibration battery's reference specimens into the lab, on the side
# that produces them.
#
#   bash compiler/eval/calibration/tools/make-battery.sh
#   VG_CAL_LAB=/somewhere bash compiler/eval/calibration/tools/make-battery.sh
#
# WHAT THIS IS
#
# A calibration battery in the metrological sense: a set of reference specimens
# whose true value is established BEFORE any probe is pointed at them, so that a
# probe can be qualified by being made to read them rather than by having its
# error model argued from its source. This script is the standard. The specimens
# are its output and are never committed -- interfaces.md section 1, and the same
# rule tools/make-ladder.sh is written under: a fixture committed under compiler/
# is a measurement input in the published tree.
#
# Because the specimens are not committed, THIS SCRIPT is what a reviewer reads,
# and its sha-256 is what pins the standard. scripts/run-battery.sh recomputes
# that digest and refuses to measure when it has moved without battery.json's
# `generatorSha256` moving with it: a generator that changed is a different
# standard, and a standard that can change silently is not one.
#
# WHAT A "TRUE VALUE" MEANS HERE, AND WHY IT IS NOT THE PROBE'S OWN READING
#
# Every specimen below is written so that its state is decided by something other
# than the extractor being calibrated. Three channels, and every fixture names
# which of them it stands on (claims/expected.json, field `truthArgument`):
#
#   construction   the C language forbids the other readings. A wipe whose zeros
#                  are subsequently read cannot be removed by a conforming
#                  compiler, so PRESENT is not a hope about the optimiser.
#   asm-witness    compiler/eval/second-vendor/lib/asm-oracle.mjs, at the `asm`
#                  checkpoint, which is a DIFFERENT instrument at a DIFFERENT
#                  point. It is coarser -- it cannot tell LOST from
#                  NOT_APPLICABLE and has no pass attribution -- and it is used
#                  only where that coarseness does not matter.
#   defined-fns    the function names this script reads back out of the bytes it
#                  just emitted. "This name is not in the emitted file" is a fact
#                  about the file and is independent of every extractor.
#
# A fixture standing on `construction` ALONE is a single-legged truth. Those are
# marked as such in expected.json and scripts/check-battery.py reports them
# separately, because a battery that presented a one-legged truth as a two-legged
# one would be overstating its own authority.
#
# SIZE DISCIPLINE
#
# One fixture, one translation unit. The memory-object discriminator decides LOST
# from NOT_APPLICABLE by an alloca-size census within a unit, so two objects of one
# size interact with the verdict. Keeping one fixture per unit keeps that
# interaction out of the fixtures that are not measuring it -- as far as the SOURCE
# can, which is not all the way.
#
# ★ THE DISCIPLINE IS NOT SUFFICIENT, and this paragraph used to say it was.
# Measured 2026-08-17: a probe with ONE 192-byte alloca at pre-opt, promoted away,
# plus a static helper holding its own 192-byte local, reads post sizes [192] and a
# false LOST. Inlining brought a same-sized object into the unit that no
# source-level size hygiene could have predicted. Distinct sizes lower the chance of
# a census collision; they do not remove it, and a fixture whose verdict depends on
# that census should be read knowing so.
#
# Sizes are pairwise-distinct primes drawn from a band DISJOINT from the ladder's
# (the ladder uses 59..103): 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
# 163, 167, 173, 179, 181, 191, 193. Disjoint so that a specimen of this battery and a rung
# of the ladder can never be confused by size in a record read out of context.
#
# THREE fixtures deliberately break the size discipline, and each says so in its own
# comment: cw_samesize (two objects of one size, which is the arrangement the
# catalogue used to name); cw_inlinesize (one object of that size in the source and a
# second arriving by inlining, which is the arrangement that actually defeats the
# census); and cw_napp (199 bytes, chosen ABOVE the 128-byte x86-64 red zone so that
# a surviving in-memory object requires a visible stack adjustment -- that is what
# makes its NOT_APPLICABLE readable from the assembly instead of from the
# discriminator under test).
#
# OUTPUT
#
# key=value on stdout, in the shape observe-config.sh's manifests already use:
#
#   lab=<the lab root the specimens were written into>
#   fixture=<id>:<path to the emitted translation unit>
#   fn=<id>:<one function name that fixture's emitted bytes define>   (repeated)
#
# The fn lines are DERIVED from the emitted bytes, never kept beside them. A list
# kept by hand can be right about a file that has changed, and the failure it
# would let through is the observer's third silent mode: a subject name that
# resolves to nothing gives rc 0, empty stderr, a non-empty log and a held
# control, with only the subject's rows missing.
set -u

LAB=${VG_CAL_LAB:-$HOME/vg-lab/calibration}
FX="$LAB/fixtures"

# LC_ALL=C so that the sort order of the derived name list is a property of this
# script rather than of whoever's shell ran it. The bytes below are written by
# heredoc from a file the tree keeps at LF (.gitattributes: compiler/** text
# eol=lf), so the emitted specimen is LF on both sides of the mount and a digest
# taken on one side matches a digest taken on the other.
export LC_ALL=C

mkdir -p "$FX"

# ---------------------------------------------------------------------------
# The opaque environment every specimen is written against.
#
# Declared here, defined nowhere, never linked: each specimen is compiled with -c
# only. An extern the compiler cannot see through is the only portable way to
# write "the optimiser is not allowed to know this", and every irremovable effect
# and every unfoldable condition below rests on one.
# ---------------------------------------------------------------------------
PREAMBLE='/* Generated by compiler/eval/calibration/tools/make-battery.sh.
 * Never committed: interfaces.md section 1.
 *
 * Compiled with -c only. Every cb_* below is an undefined extern, so nothing
 * here is ever linked and the optimiser cannot see through any of them.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern void cb_fill(void *p, unsigned long n);
extern void cb_use(const void *p, unsigned long n);
extern int cb_cond(void);
extern void cb_deny(void);
extern void cb_sink(void);
extern void cb_take(int v);
extern int cb_validate(const void *p, unsigned long n);
'

emit() { # id, body
  local id=$1
  mkdir -p "$FX/$id"
  { printf '%s\n' "$PREAMBLE"; printf '%s\n' "$2"; } > "$FX/$id/$id.c"
}

# ===========================================================================
# SHAPE 1 of 4 -- call survival (ir.wipe-effect)
# ===========================================================================

# known-PRESENT. The zeros are read afterwards, so removing the wipe would change
# what cb_use observes and the as-if rule forbids it. PRESENT here is a
# consequence of the language, not a prediction about the optimiser.
emit cal-wipe-present '
void cw_present_subject(void) {
  unsigned char b[107];
  cb_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  cb_use(b, sizeof b);
}

void cw_present_control(void) {
  unsigned char b[109];
  cb_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  cb_use(b, sizeof b);
}
'

# known-LOST. The wipe is last and nobody reads the zeros, so it is dead. The
# buffer has already escaped to an opaque consumer BEFORE the wipe, which is what
# separates this from cal-wipe-napp: the object cannot be promoted out of memory,
# so when the count reaches zero the referent is still there and the reading is a
# loss rather than a change of subject. The control wipes and is then read, so it
# cannot go with it.
emit cal-wipe-lost '
void cw_lost_subject(void) {
  unsigned char b[113];
  cb_fill(b, sizeof b);
  cb_use(b, sizeof b);
  memset(b, 0, sizeof b);
}

void cw_lost_control(void) {
  unsigned char b[127];
  cb_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  cb_use(b, sizeof b);
}
'

# known-NOT_APPLICABLE. Nothing escapes and nothing is read, so the whole object
# is dead and the compiler is entitled to remove it entirely -- at which point the
# question "was the wipe removed" has lost its referent and is NOT_APPLICABLE
# rather than LOST.
#
# 199 bytes, and the size is the point. x86-64 leaf functions may keep up to 128
# bytes below %rsp (the red zone) without adjusting the stack pointer, so an
# object smaller than that can survive in memory with no visible stack
# adjustment. At 199 an object that is still in memory REQUIRES a visible frame
# of at least 199 bytes, so "no such adjustment in the emitted body" is a reading
# of the assembly that says the object is gone. That is the independent leg: it
# does not consult the alloca-size census, which is the thing being calibrated.
emit cal-wipe-napp '
void cw_napp_subject(void) {
  unsigned char b[199];
  for (unsigned i = 0; i < 199; i++) b[i] = (unsigned char)i;
  memset(b, 0, sizeof b);
}

void cw_napp_control(void) {
  unsigned char b[131];
  cb_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  cb_use(b, sizeof b);
}
'

# known-BROKEN_MEASUREMENT, at an optimising level only. Both units have a dead
# wipe, so the CONTROL goes with the subject and interfaces.md section 4 makes the
# cell a broken measurement rather than a finding.
#
# The pair matters in both directions. At -O0 neither wipe is removed, the control
# holds, and this fixture must NOT read broken; a fixture that reported a broken
# apparatus at every level would be indistinguishable from a harness that always
# says so, which is the negative-controls doctrine applied to an apparatus column.
emit cal-wipe-broken '
void cw_broken_subject(void) {
  unsigned char b[137];
  cb_fill(b, sizeof b);
  cb_use(b, sizeof b);
  memset(b, 0, sizeof b);
}

void cw_broken_control(void) {
  unsigned char b[139];
  cb_fill(b, sizeof b);
  cb_use(b, sizeof b);
  memset(b, 0, sizeof b);
}
'

# Instrument-limit probe for ir.wipe-effect degradationRisk[0] -- indirect calls
# are not counted, because CallBase::getCalledFunction returns null for them.
#
# The pointer is `volatile`, so the compiler must re-read it at every call and
# cannot devirtualise the call back into a direct one. The value it reads is the
# one the initialiser put there and no other writer exists, so the call provably
# goes to memset: the property IS enforced and the true value is PRESENT.
#
# The control is a DIRECT wipe at the same optimisation level. That is what makes
# a reading of ABSENT on the subject a false negative rather than a blind oracle:
# the extractor demonstrably still sees a memset here.
emit cal-wipe-indirect '
typedef void *(*cw_wipe_fn)(void *, int, unsigned long);
static volatile cw_wipe_fn cw_wiper = memset;

void cw_indirect_subject(void) {
  unsigned char b[149];
  cb_fill(b, sizeof b);
  cw_wiper(b, 0, sizeof b);
  cb_use(b, sizeof b);
}

void cw_indirect_control(void) {
  unsigned char b[151];
  cb_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  cb_use(b, sizeof b);
}
'

# Instrument-limit probe for ir.wipe-effect degradationRisk[1] -- the
# promoted-object test matches by allocation size, so two allocas of one size in
# a unit make "an object of that size survives" true even when the wiped one was
# promoted.
#
# 192 and 192, deliberately equal and deliberately not prime: this fixture exists
# to break the size discipline the rest of the battery keeps, and a reader who
# finds a repeated non-prime size here should find this paragraph with it. `dead`
# is promotable; `pinned` escapes and is the same size.
emit cal-wipe-samesize '
void cw_samesize_subject(void) {
  unsigned char dead[192];
  unsigned char pinned[192];
  for (unsigned i = 0; i < 192; i++) dead[i] = (unsigned char)i;
  memset(dead, 0, sizeof dead);
  cb_fill(pinned, sizeof pinned);
  cb_use(pinned, sizeof pinned);
}

void cw_samesize_control(void) {
  unsigned char b[157];
  cb_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  cb_use(b, sizeof b);
}
'

# Instrument-limit probe for a degradation compiler/schema/properties.json does
# NOT record, found by running this battery on 2026-08-17 and confirmed at
# src/Extractors.cpp:237-246.
#
# The zero-store half of ir.wipe-effect counts ANY store of a null constant whose
# underlying object is an alloca or a pointer argument. There is no requirement
# that the object be the one the property is about, no size floor, and no relation
# to the configured effect symbol. So `int flag = 0;` -- an ordinary
# zero-initialised local -- is counted as the wipe.
#
# Here the real wipe is dead and goes, while `flag`'s zero store survives because
# its address is read. The subject's effect count therefore stays at one and the
# cell reads PRESENT while the property is LOST. That is the DANGEROUS direction
# for a must-survive property: the reading says the defence is there.
#
# The catalogue's existing sentences about this half say only what it MISSES (a
# non-zero fill byte, a vectorised loop). What it spuriously COUNTS is not in
# them, which is why this cell is in the battery and a new claim is in
# claims/degradation-claims.json marked as an omission rather than a disagreement.
# The statement ORDER is load-bearing and was wrong on the first attempt. With
# `cb_use(&flag, ...)` written AFTER the wipe, the wipe was not dead: an opaque
# call standing after it may observe the zeros through the pointer that already
# escaped, so clang kept the zeroing and the cell measured nothing. The escape of
# `&flag` therefore happens BEFORE the wipe, and the wipe is the last statement in
# the function, exactly as in cal-wipe-lost. The fixture was changed; the
# expectation was not.
emit cal-wipe-zeroinit '
void cw_zeroinit_subject(void) {
  unsigned char b[181];
  int flag = 0;
  cb_fill(b, sizeof b);
  cb_use(&flag, sizeof flag);
  cb_use(b, sizeof b);
  memset(b, 0, sizeof b);
}

void cw_zeroinit_control(void) {
  unsigned char b[191];
  cb_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  cb_use(b, sizeof b);
}
'

# Instrument-limit probe for the CORRECTED ir.wipe-effect degradationRisk[1], and
# the cell that correction is owed to.
#
# The census is defeated not by two same-size objects in the source -- cal-wipe-samesize
# shows it handles those correctly -- but by a pass that CREATES an object of the
# effect's size while the subject's is promoted, which holds the count steady.
# Inlining is such a pass, so no source-level size discipline can prevent it.
#
# `dead` never escapes and nothing reads it, so it is promoted out of memory and the
# true value is NOT_APPLICABLE. The static helper carries its OWN 192-byte local and
# is inlined into the subject, so a 192-byte object is allocated in the unit after
# the promotion that was not there before it. Census: one 192 before, one 192 after,
# count steady, verdict LOST for a buffer that left memory.
#
# This probe existed only as a paragraph in a JSON string until an adversarial pass
# pointed out that the correction it produced -- which DEMOTED this battery's own
# size-discipline rationale -- was resting on a one-off measurement nobody could
# re-run. A finding heavy enough to move the standard is heavy enough to be a cell.
emit cal-wipe-inlinesize '
static void cw_inlinesize_helper(void) {
  unsigned char h[192];
  cb_fill(h, sizeof h);
  cb_use(h, sizeof h);
}

void cw_inlinesize_subject(void) {
  unsigned char dead[192];
  for (unsigned i = 0; i < 192; i++) dead[i] = (unsigned char)i;
  memset(dead, 0, sizeof dead);
  cw_inlinesize_helper();
}

void cw_inlinesize_control(void) {
  unsigned char b[193];
  cb_fill(b, sizeof b);
  memset(b, 0, sizeof b);
  cb_use(b, sizeof b);
}
'

# ===========================================================================
# SHAPE 2 of 4 -- guarded call (ir.guarded-call)
# ===========================================================================

# known-PRESENT. The condition comes from outside the unit, so neither the branch
# nor the call it leads to can be folded.
emit cal-guard-present '
void cg_present_subject(void) { if (cb_cond()) cb_deny(); }

void cg_present_control(void) { if (cb_cond()) cb_deny(); }
'

# known-LOST. The condition is a static the optimiser can prove is zero, so the
# branch is decided at compile time and the deny path is unreachable: no
# authorisation decision is taken at run time any more.
#
# NOT `const`. A const initialiser is folded by the FRONT END, so the branch never
# reaches the IR at all and the cell reads ABSENT at every level, discriminating
# nothing -- measured on the ladder's c1 rung, 2026-08-17. Written once and never
# again, so it is the optimiser rather than the front end that decides it.
emit cal-guard-lost '
static int cg_lost_zero = 0;

void cg_lost_subject(void) { if (cg_lost_zero) cb_deny(); }

void cg_lost_control(void) { if (cb_cond()) cb_deny(); }
'

# known-NOT_APPLICABLE. For this extractor NOT_APPLICABLE has exactly one cause --
# the unit was inlined away -- because a branch has no memory object to be
# promoted out of. A static function with one call site is inlined and its
# out-of-line copy deleted.
#
# The independent leg is the emitted assembly: at -O0 the listing carries a
# `cg_napp_subject:` label and at -O2 it does not. That is a fact about the bytes,
# and it is what tells this apart from the observer failing to resolve a name --
# which is why expected.json declares `expectDefinedInAsm` per configuration and
# scripts/check-battery.py treats a disagreement in EITHER direction as a check
# that could not be completed rather than as a reading.
emit cal-guard-napp '
static void cg_napp_subject(void) { if (cb_cond()) cb_deny(); }

void cg_napp_caller(void) { cg_napp_subject(); }

void cg_napp_control(void) { if (cb_cond()) cb_deny(); }
'

# known-BROKEN_MEASUREMENT at an optimising level. The control'"'"'s condition is
# foldable too, so the control goes with the subject. Held at -O0, for the same
# both-directions reason as cal-wipe-broken.
emit cal-guard-broken '
static int cg_broken_zero_s = 0;
static int cg_broken_zero_c = 0;

void cg_broken_subject(void) { if (cg_broken_zero_s) cb_deny(); }

void cg_broken_control(void) { if (cg_broken_zero_c) cb_deny(); }
'

# Instrument-limit probe for ir.guarded-call degradationRisk[0] -- the live-branch
# test is per UNIT, not per call, so another live conditional branch elsewhere in
# the same function keeps an already-folded guard counted.
#
# cg_perunit_on folds to true, which makes the deny call UNCONDITIONAL: the guard
# no longer decides anything at run time, and the property is not enforced. The
# second `if` is unrelated and stays live, which satisfies the per-unit gate.
#
# This is the extractor'"'"'s dangerous direction -- it errs towards PRESENT, and
# properties.json says so and marks the extractor implemented only for the
# single-guard shape its own fixture has. Measuring it is the point of this cell.
emit cal-guard-perunit '
static int cg_perunit_on = 1;

void cg_perunit_subject(void) {
  if (cg_perunit_on) cb_deny();
  if (cb_cond()) cb_sink();
}

void cg_perunit_control(void) { if (cb_cond()) cb_deny(); }
'

# ===========================================================================
# SHAPE 3 of 4 -- forbidden callee (ir.forbidden-callee), opposite polarity:
# a non-zero count is the finding, and the control is a unit where the forbidden
# call is certainly still present.
# ===========================================================================

# known-PRESENT, meaning the forbidden call is there and the finding is real. The
# format string consumes a value the compiler cannot know, so the call cannot be
# rewritten into puts.
emit cal-forbid-hit '
void cf_hit_subject(void) { printf("cal %d\n", cb_cond()); }

void cf_hit_control(void) { printf("cal %d\n", cb_cond()); }
'

# known-ABSENT, and this is the cell the catalogue says is missing elsewhere in
# the tree: an extractor of this polarity that has only ever been shown to FIRE
# has not been shown to stop firing. The subject names no forbidden symbol; the
# control calls one and consumes its result, so it cannot be removed.
#
# getenv is chosen because no optimisation introduces it. A forbidden list naming
# a memory intrinsic would be met by the compiler synthesising one, and a clean
# reading would then be luck.
emit cal-forbid-clean '
void cf_clean_subject(void) { cb_sink(); }

void cf_clean_control(void) { cb_take(getenv("CAL_ABSENT_NAME") != 0); }
'

# known-BROKEN_MEASUREMENT above -O0. The control is a constant-string printf,
# which clang rewrites into puts, so a control read through the `printf` list
# falls to zero while the subject'"'"'s printf survives. That is not a finding
# about the subject: interfaces.md section 4 makes it a broken measurement, and
# the ladder measured this exact rewrite on its d1 rungs.
emit cal-forbid-broken '
void cf_broken_subject(void) { printf("cal %d\n", cb_cond()); }

void cf_broken_control(void) { printf("cal\n"); }
'

# Instrument-limit probe for ir.forbidden-callee degradationRisk[1] -- indirect
# calls are not counted, so a forbidden entry point reached through a table reads
# as absent.
#
# This is the worst direction any extractor in this tree fails in: silence about a
# must-not-appear property. The pointer is volatile and its only writer is the
# initialiser, so the forbidden entry point IS reached and the true value is a
# hit. The control calls the same entry point directly, so the extractor is
# demonstrably still able to see one at this level.
#
# `noinline` on the entry point, and it is not decoration. Without it the FIRST
# measurement of this cell read a fallen control at -O2: clang inlined
# cf_forbidden_entry into the control, the direct call disappeared, and the cell
# became a broken measurement rather than the instrument-limit reading it exists
# to take. A control has to be countable at EVERY checkpoint -- the same lesson
# tools/make-ladder.sh records at its a3_twin, where a wipe behind a static helper
# was not there yet at the pre-optimisation checkpoint and took a whole rung out.
# The fixture was changed; the expectation was not.
emit cal-forbid-indirect '
__attribute__((noinline)) void cf_forbidden_entry(void) { cb_sink(); }

typedef void (*cf_entry_fn)(void);
static volatile cf_entry_fn cf_table = cf_forbidden_entry;

void cf_indirect_subject(void) { cf_table(); }

void cf_indirect_control(void) { cf_forbidden_entry(); }
'

# ===========================================================================
# SHAPE 4 of 4 -- dominance. THERE IS NO EXTRACTOR FOR THIS SHAPE.
#
# compiler/schema/properties.json, property survive.input-validation:
# `extractor: null`, and its controlRule says outright that a control for a
# dominance property is not the same shape as a control for a count. So these two
# specimens are emitted and never measured, and the report carries the lane with a
# status word rather than omitting it.
#
# They are here because a calibration standard that pre-dates its probe is the
# metrologically correct order: whoever writes the dominance extractor has to make
# it read a set it did not choose. A battery assembled afterwards by the same hand
# that wrote the probe would be that probe'"'"'s own homework.
# ===========================================================================

emit cal-dom-present '
void cd_present_subject(void) {
  unsigned char b[163];
  cb_fill(b, sizeof b);
  if (!cb_validate(b, sizeof b)) return;
  cb_use(b, sizeof b);
}

void cd_present_control(void) {
  unsigned char b[167];
  cb_fill(b, sizeof b);
  if (!cb_validate(b, sizeof b)) return;
  cb_use(b, sizeof b);
}
'

emit cal-dom-lost '
void cd_lost_subject(void) {
  unsigned char b[173];
  cb_fill(b, sizeof b);
  cb_use(b, sizeof b);
  if (!cb_validate(b, sizeof b)) return;
  cb_sink();
}

void cd_lost_control(void) {
  unsigned char b[179];
  cb_fill(b, sizeof b);
  if (!cb_validate(b, sizeof b)) return;
  cb_use(b, sizeof b);
}
'

# ---------------------------------------------------------------------------
# Read the names back out of the bytes that were just written.
#
# Same predicate as tools/make-ladder.sh: a name followed by a parameter list with
# no nested parentheses and then an opening brace. Every definition above
# satisfies that on one line or on the line the brace opens; the declarations in
# the preamble end in `;` and the call sites inside bodies are followed by `;` or
# by another `)`, so neither can be mistaken for a definition.
#
# An empty list for any fixture is refused here rather than downstream, because an
# empty list makes every name check pass vacuously -- which is the whole failure
# this output exists to prevent.
# ---------------------------------------------------------------------------
echo "lab=$LAB"

rc=0
for dir in "$FX"/cal-*; do
  id=$(basename "$dir")
  src="$dir/$id.c"
  if [ ! -s "$src" ]; then
    echo "make-battery.sh: $id: nothing was emitted at $src" >&2
    rc=1
    continue
  fi
  echo "fixture=$id:$src"
  defined=$(grep -oE '\b(cw|cg|cf|cd)_[A-Za-z0-9_]*[[:space:]]*\([^()]*\)[[:space:]]*\{' "$src" \
            | sed -E 's/[[:space:]]*\(.*$//' | sort -u)
  if [ -z "$defined" ]; then
    echo "make-battery.sh: $id: no function definitions were found in $src" >&2
    rc=1
    continue
  fi
  printf '%s\n' "$defined" | sed "s/^/fn=$id:/"
done

exit $rc
