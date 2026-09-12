#!/bin/bash
# Write this lane's measurement inputs into the lab, on the side that produces
# them.
#
#   bash compiler/eval/lto-window/tools/make-lto-fixtures.sh
#   LTOW_LAB=/somewhere bash compiler/eval/lto-window/tools/make-lto-fixtures.sh
#
# Generated rather than committed, for the reason
# compiler/llvm-pass/tools/make-fixtures.sh gives: a fixture under compiler/ is a
# measurement input in the published tree, which
# scripts/check-packaging-invariants.mjs refuses outright (any path segment
# `fixtures` or `_results`). This script IS the fixture and is reviewable as one.
#
# Three families, and the differences between them are the whole point of the
# lane.
#
#   xtu         the wipe helper lives in a second translation unit. No compile
#               can see it; a full-LTO link inlines it and then deletes the
#               store. The loss exists only inside the link, so only a link-time
#               window can attribute it.
#
#   xtu-inline  the same translation units, WITHOUT the noinline intervention.
#               See the capitals below: this family exists to be measured, not to
#               be fixed.
#
#   erasure     subject and control in one unit, the shape
#               compiler/llvm-pass/tools/make-fixtures.sh generates. The loss is
#               complete before the link starts. It is here as the contrast: a
#               link-time window must report ABSENT-throughout for it rather than
#               manufacture a link-time loss.
#
# Every family carries a positive control beside the subject, because "the wipe
# was removed" and "the observer stopped seeing wipes" produce the same number
# when only the subject is looked at.
#
# THIS SCRIPT MAKES EXACTLY ONE INTERVENTION, AND EMITS ONE FAMILY THAT CARRIES
# IT AND ONE FAMILY THAT DOES NOT.
#
#   The intervention is `__attribute__((noinline))` on the subject and on the
#   control. `xtu` carries it. `xtu-inline` is the same four translation units
#   with those two lines deleted and nothing else changed -- both are emitted
#   from one template, by two seds, so "nothing else changed" is checkable with
#   `diff` rather than asserted (the command is printed at the end of this
#   script). `erasure` carries the intervention too, for the same reason `xtu`
#   does.
#
#   Why `xtu` carries it: a (pass, unit) attribution needs a unit for its second
#   half. Without the attribute, full LTO is free to absorb `handle` and
#   `wipe_kept` into `main`, and an observer that cannot resolve `handle` as a
#   unit has nothing to hang `DSEPass on handle` on.
#
#   Why `xtu-inline` exists anyway, and what it is NOT: it is not the fixture
#   repaired, and it is not a second sample of the same measurement. It is the
#   measurement of what the intervention costs. The pair is there to separate two
#   claims that the intervened family alone cannot separate:
#
#     the ELIMINATION    -- the store is gone from the linked program. This does
#                           not depend on the attribute, and the independent
#                           disassembly reader (tools/read-wipe.py, through
#                           gcc-repair's objdump oracle) can be asked about it in
#                           either family, because it reads the artifact rather
#                           than the pass pipeline.
#
#     the ATTRIBUTION    -- WHICH pass removed it, in WHICH IR unit. This does
#                           depend on the attribute, and the expected outcome for
#                           `xtu-inline` is that it becomes impossible: no unit
#                           named `handle` survives for a (pass, unit) pair to
#                           name, so the cell is OK with NOT_OBSERVED rather than
#                           a result.
#
#   So a reader who says "you only saw it because of noinline" is half right, and
#   the pair is what says which half. What the attribute buys is the unit to
#   attribute TO; what it does not buy is the disappearance.
#
#   Nothing else about the wipes is changed in either family: the helper is still
#   inlined into the subject, which is the merge this lane is about.
set -u

LAB=${LTOW_LAB:-$HOME/vg-lab/lto-window}
FX="$LAB/fixtures"
mkdir -p "$FX/xtu" "$FX/xtu-inline" "$FX/erasure"

# ------------------------------------------------------------------ xtu --
#
# io.c is compiled WITHOUT -flto on purpose. It is the opacity the fixture needs:
# with `derive` and `use` visible to the link, SROA promotes the buffer out of
# memory and the control stops being a control -- measured, and it is exactly
# what happens to the erasure family below. Keeping one unit out of the merged
# module is how a control survives a whole-program optimiser.
cat > "$FX/xtu/io.c" <<'FIXTURE_EOF'
/* Producer and consumer, never compiled -flto, so the link cannot see into
 * them and the buffers they touch have to stay in memory. */

volatile unsigned char sink;

void derive(unsigned char *out, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) out[i] = (unsigned char)(i * 7u + 1u);
}

void use(const unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) sink ^= p[i];
}
FIXTURE_EOF

cat > "$FX/xtu/wipe.c" <<'FIXTURE_EOF'
/* The wipe helper, alone in its own translation unit. Compiled -flto, so the
 * link -- and only the link -- can inline it into its caller. */

#include <string.h>

void secure_wipe(void *p, unsigned long n) { memset(p, 0, n); }
FIXTURE_EOF

# use.c is the ONLY file the intervention touches, so it is written through a
# function rather than straight to a path: the same bytes are emitted twice, once
# with @NOINLINE@ replaced by the attribute (family `xtu`) and once with those
# lines deleted outright (family `xtu-inline`). Emitting both from one template
# is what makes "the two families differ by exactly the intervention" a property
# of the generator instead of a claim in a comment -- `diff` on the two files
# shows two deleted lines and nothing else.
xtu_use_c() {
cat <<'FIXTURE_EOF'
/* Subject and control, in the unit that calls the helper.
 *
 * handle()    SUBJECT. Its wipe is a call into another unit, so at compile time
 *             there is no wipe in this function at all -- the observer records
 *             ABSENT and has nothing to attribute. The link inlines the helper
 *             (the effect becomes PRESENT) and then removes the store, because
 *             it is the last use of a stack buffer. PRESENT -> LOST, inside the
 *             link.
 *
 * wipe_kept() CONTROL. Its wipe is spelled here rather than reached through the
 *             helper, so it is PRESENT in BOTH windows: at compile time it is
 *             what shows the observer can still see a wipe, and at link time it
 *             is what shows the link-time observer is still working while the
 *             subject's wipe disappears. Its buffer is read afterwards by a
 *             function the link cannot see into, so no level may remove it.
 *
 * noinline:   see the header of the generator. In family `xtu` the two
 *             attribute lines below are present; in family `xtu-inline` they are
 *             deleted and NOTHING else differs. The second family is not the
 *             first one fixed -- it is the measurement of what the attribute
 *             buys, which is a unit for an attribution to name, and what it does
 *             not buy, which is the disappearance itself. */

#include <string.h>

/* io.c -- never compiled -flto. */
void derive(unsigned char *out, unsigned long n);
void use(const unsigned char *p, unsigned long n);

/* wipe.c -- compiled -flto. */
void secure_wipe(void *p, unsigned long n);

@NOINLINE@
void handle(void) {
    unsigned char key[32];
    derive(key, sizeof key);
    use(key, sizeof key);
    secure_wipe(key, sizeof key);
}

@NOINLINE@
void wipe_kept(void) {
    unsigned char keep[32];
    derive(keep, sizeof keep);
    memset(keep, 0, sizeof keep);
    use(keep, sizeof keep);
}
FIXTURE_EOF
}

xtu_use_c | sed 's/^@NOINLINE@$/__attribute__((noinline))/' > "$FX/xtu/use.c"

cat > "$FX/xtu/main.c" <<'FIXTURE_EOF'
void handle(void);
void wipe_kept(void);

int main(void) {
    handle();
    wipe_kept();
    return 0;
}
FIXTURE_EOF

# ----------------------------------------------------------- xtu-inline --
#
# The same four translation units with the intervention removed, and removed in
# the one place it lives: `use.c`. The other three files are COPIED rather than
# re-emitted, so nothing can drift between the families by an edit that touches
# one heredoc and not the other.
#
# This family is expected to produce a WORSE reading than `xtu`, and that is the
# result it is here for. `handle` and `wipe_kept` are absorbed into `main`, the
# observer loses the unit it would attribute a loss to, and the link cell comes
# back OK with NOT_OBSERVED rather than `DSEPass on handle`. What does NOT change
# is whether the store is in the linked program -- that question is answered from
# the artifact, by the disassembly reader, in both families.
for f in io.c wipe.c main.c; do cp "$FX/xtu/$f" "$FX/xtu-inline/$f"; done
xtu_use_c | sed '/^@NOINLINE@$/d' > "$FX/xtu-inline/use.c"

# -------------------------------------------------------------- erasure --
#
# The three files compiler/llvm-pass/tools/make-fixtures.sh writes for the
# erasure family, with the two noinline attributes added for the reason at the
# top. Kept comparable in shape so a reader can see it is the same subject.
cat > "$FX/erasure/opaque.c" <<'FIXTURE_EOF'
/* Producer and consumer in a separate translation unit. Under -flto this unit is
 * bitcode like the others, so the link CAN see into it -- which is the whole
 * difference from xtu/io.c, and it costs this family its control. */

volatile unsigned char sink;

void get_secret(unsigned char *out, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) out[i] = (unsigned char)(i * 7u + 1u);
}

void consume(const unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) sink ^= p[i];
}
FIXTURE_EOF

cat > "$FX/erasure/target.c" <<'FIXTURE_EOF'
/* Secure erasure: a wipe that -O2 is entitled to delete, next to one it is not.
 * Subject and control in one translation unit, so that "the wipe was removed"
 * cannot be confused with "the observer stopped recognising wipes here". */

#include <string.h>

/* opaque.c */
void get_secret(unsigned char *out, unsigned long n);
void consume(const unsigned char *p, unsigned long n);

/* Subject. The wipe is the last use of the buffer: a dead store, and the
 * COMPILE is entitled to delete it at -O2. */
__attribute__((noinline))
void handle_request(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    consume(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
}

/* Control at COMPILE time. The wipe is read afterwards, so no optimisation
 * level may delete it -- as long as `consume` is opaque. Under full LTO it is
 * not opaque, the buffer is promoted out of memory, and this stops being a
 * control. That is measured, not assumed, and it is why this family's link-time
 * cell is a broken measurement rather than a result. */
__attribute__((noinline))
void wipe_kept(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
    consume(secret, sizeof secret);
}
FIXTURE_EOF

cat > "$FX/erasure/main.c" <<'FIXTURE_EOF'
void handle_request(void);
void wipe_kept(void);

int main(void) {
    handle_request();
    wipe_kept();
    return 0;
}
FIXTURE_EOF

echo "lto-window fixtures written to $FX"
# The intervention, stated as a command rather than as a sentence. Two deleted
# lines, both of them the attribute, and nothing else -- if this ever prints
# anything more, the two families stopped being a pair and the lane's claim about
# what the attribute buys stopped being about one variable.
echo "the only difference between the two xtu families:"
diff "$FX/xtu/use.c" "$FX/xtu-inline/use.c"
echo "(a diff showing exactly two deleted __attribute__((noinline)) lines is the expected output)"
