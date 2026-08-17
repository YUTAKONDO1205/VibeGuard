#!/bin/bash
# Measurement inputs for the metadata/structure dual channel (design plan section 10.4).
#
#   bash compiler/llvm-pass/tools/make-dual-channel-fixtures.sh
#   IRCK_DUAL_LAB=/somewhere bash compiler/llvm-pass/tools/make-dual-channel-fixtures.sh
#
# Same rule as tools/make-fixtures.sh: fixtures are generated into the lab and
# never committed under compiler/, so this script IS the fixture and is
# reviewable as one. It writes into its own lab directory rather than the
# optimisation matrix's, so a dual-channel run cannot overwrite a matrix run.
#
# What each function is for is written next to it, because the whole point of
# these fixtures is that four different things can happen to one property and a
# fixture whose intent is not written down cannot show which one did.
set -u

LAB=${IRCK_DUAL_LAB:-$HOME/vg-lab/llvm-pass-dual}
FX="$LAB/fixtures"

mkdir -p "$FX/dual"

# The second translation unit. `fill` and `sink` are defined here and only
# declared in target.c, so the optimiser cannot see through them and cannot use
# their bodies as the explanation for anything the subject does.
cat > "$FX/dual/opaque.c" <<'FIXTURE_EOF'
volatile unsigned char observed;

void fill(char *p, unsigned n) {
    for (unsigned i = 0; i < n; i++) p[i] = (char)(i + 1);
}

void sink(void *p) { observed = *(unsigned char *)p; }
FIXTURE_EOF

cat > "$FX/dual/main.c" <<'FIXTURE_EOF'
void red_subject(void);
void both_survive(void);
void metadata_lies(void);
void both_erased(void);
void wipe_kept(char *out);

int main(void) {
    char out[4];
    red_subject();
    both_survive();
    metadata_lies();
    both_erased();
    wipe_kept(out);
    return out[0];
}
FIXTURE_EOF

cat > "$FX/dual/target.c" <<'FIXTURE_EOF'
/* Four subjects, one control, one translation unit.
 *
 * Every one of them declares the same property the same way -- the wipe is
 * annotated with `vg:property:erasure.wipe` -- and the four subjects differ
 * only in what the optimiser is then able to do to the declaration and to the
 * processing. That is the experiment: the declaration and the processing are
 * two representations of one property, and each can go without the other.
 */
#include <string.h>

void sink(void *p);
void fill(char *p, unsigned n);

/* Deliberately not `const`. A `const` initialiser is folded by the *front end*,
 * which would delete the annotated block before the pre-optimisation
 * checkpoint ever sees it -- measured: the annotation then reads zero at both
 * checkpoints, which is "never declared", not "erased". Left non-const, the
 * block reaches the first checkpoint and the *optimiser* is the one that
 * removes it. Nothing in the program writes it, so it can. */
static int diagnostic_mode = 0;

/* CONTROL. Annotated, and its wipe is read afterwards, so neither channel can
 * lose anything here. A run where this control's annotation or effect goes is a
 * broken measurement, not a finding -- the same rule the structural channel's
 * control already obeys. */
__attribute__((annotate("vg:property:erasure.wipe")))
__attribute__((noinline))
void wipe_kept(char *out) {
    char keep[16];
    fill(keep, 16);
    memset(keep, 0, 16);
    sink(keep);
    out[0] = keep[0];
}

/* SUBJECT A -- the case §10.4 names: the metadata goes and the processing
 * stays. The annotation is inside a block the optimiser proves unreachable, so
 * it is deleted with that block; the wipe on the live path is read afterwards
 * and survives. An observer with only a metadata channel calls this a lost
 * property. It is not: the program still wipes. */
/* The 32 is not arbitrary. The structural channel's LOST/NOT_APPLICABLE
 * discriminator identifies the wiped object by a census of alloca sizes when
 * names have been discarded, which they are above -O0. Two 16-byte buffers in
 * one unit, one of which leaves, makes that census read "an object of this size
 * left" for both of them -- measured: `both_erased` read NOT_APPLICABLE with
 * two 16-byte buffers. That is the structural channel's own known limit and
 * `promotion-decoy` in the optimisation matrix is the fixture for it. Mixing it
 * in here would make these cells test two things at once, so the sizes are kept
 * apart and these cells test the pair of channels only. */
__attribute__((noinline))
void red_subject(void) {
    if (diagnostic_mode) {
        __attribute__((annotate("vg:property:erasure.wipe"))) char scratch[32];
        fill(scratch, 32);
        memset(scratch, 0, 32);
        sink(scratch);
    }
    char token[16];
    fill(token, 16);
    memset(token, 0, 16);
    sink(token);
}

/* SUBJECT B -- the positive control for the pair: both channels survive. */
__attribute__((annotate("vg:property:erasure.wipe")))
__attribute__((noinline))
void both_survive(void) {
    char token[16];
    fill(token, 16);
    memset(token, 0, 16);
    sink(token);
}

/* SUBJECT C -- the opposite failure: the declaration survives and the
 * processing is deleted. The wipe is the last thing done to a buffer nobody
 * reads again, so it is a dead store. An observer with only a metadata channel
 * calls this clean. */
__attribute__((annotate("vg:property:erasure.wipe")))
__attribute__((noinline))
void metadata_lies(void) {
    char token[16];
    fill(token, 16);
    sink(token);
    memset(token, 0, 16);
}

/* SUBJECT D -- both go. Subject A's folded block, subject C's dead store. */
__attribute__((noinline))
void both_erased(void) {
    if (diagnostic_mode) {
        __attribute__((annotate("vg:property:erasure.wipe"))) char scratch[32];
        fill(scratch, 32);
        memset(scratch, 0, 32);
        sink(scratch);
    }
    char token[16];
    fill(token, 16);
    sink(token);
    memset(token, 0, 16);
}
FIXTURE_EOF

# The same program with every annotation removed. This is what the metadata
# channel has to read as "nothing was declared here" -- if a module with no
# annotations at all produced the §10.4 headline state, the state would be a
# default rather than a measurement.
mkdir -p "$FX/plain"
cp "$FX/dual/opaque.c" "$FX/plain/opaque.c"
cp "$FX/dual/main.c" "$FX/plain/main.c"
sed -e 's/^__attribute__((annotate("vg:property:erasure.wipe")))$//' \
    -e 's/__attribute__((annotate("vg:property:erasure.wipe"))) char scratch/char scratch/' \
    "$FX/dual/target.c" > "$FX/plain/target.c"

# Guard on the attribute itself, not on the word: the prose above it says
# "annotated" a dozen times and a guard that fired on prose would have to be
# switched off, which is how guards stop guarding.
if grep -q '__attribute__((annotate' "$FX/plain/target.c"; then
    echo "make-dual-channel-fixtures.sh: the plain fixture still carries an annotation" >&2
    exit 1
fi

echo "dual-channel fixtures -> $FX"
