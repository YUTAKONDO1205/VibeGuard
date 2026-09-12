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
# Two families, and the difference between them is the whole point of the lane.
#
#   xtu      the wipe helper lives in a second translation unit. No compile can
#            see it; a full-LTO link inlines it and then deletes the store. The
#            loss exists only inside the link, so only a link-time window can
#            attribute it.
#
#   erasure  subject and control in one unit, the shape
#            compiler/llvm-pass/tools/make-fixtures.sh generates. The loss is
#            complete before the link starts. It is here as the contrast: a
#            link-time window must report ABSENT-throughout for it rather than
#            manufacture a link-time loss.
#
# Both families carry a positive control beside the subject, because "the wipe
# was removed" and "the observer stopped seeing wipes" produce the same number
# when only the subject is looked at.
#
# THE noinline ATTRIBUTES ARE A FIXTURE INTERVENTION AND ARE DECLARED AS ONE.
# Measured first without them: full LTO inlines both `handle` and `wipe_kept`
# into `main`, and the linked executable defines neither (`nm` showed only
# `main`). A (pass, unit) attribution needs a unit for its second half, so the
# subject and the control are held out of line. Nothing else about the wipes is
# changed: the helper is still inlined into the subject, which is the merge this
# lane is about.
set -u

LAB=${LTOW_LAB:-$HOME/vg-lab/lto-window}
FX="$LAB/fixtures"
mkdir -p "$FX/xtu" "$FX/erasure"

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

cat > "$FX/xtu/use.c" <<'FIXTURE_EOF'
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
 * noinline: see the header of this script. Without it full LTO inlines both of
 * these into main and there is no unit left for an attribution to name. */

#include <string.h>

/* io.c -- never compiled -flto. */
void derive(unsigned char *out, unsigned long n);
void use(const unsigned char *p, unsigned long n);

/* wipe.c -- compiled -flto. */
void secure_wipe(void *p, unsigned long n);

__attribute__((noinline))
void handle(void) {
    unsigned char key[32];
    derive(key, sizeof key);
    use(key, sizeof key);
    secure_wipe(key, sizeof key);
}

__attribute__((noinline))
void wipe_kept(void) {
    unsigned char keep[32];
    derive(keep, sizeof keep);
    memset(keep, 0, sizeof keep);
    use(keep, sizeof keep);
}
FIXTURE_EOF

cat > "$FX/xtu/main.c" <<'FIXTURE_EOF'
void handle(void);
void wipe_kept(void);

int main(void) {
    handle();
    wipe_kept();
    return 0;
}
FIXTURE_EOF

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
