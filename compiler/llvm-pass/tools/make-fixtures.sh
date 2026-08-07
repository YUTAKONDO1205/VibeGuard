#!/bin/bash
# Write the measurement inputs into the lab, on the side that produces them.
#
#   bash compiler/llvm-pass/tools/make-fixtures.sh
#   IRCK_LAB=/somewhere bash compiler/llvm-pass/tools/make-fixtures.sh
#
# The fixtures are generated rather than committed because a fixture under
# compiler/ is a measurement input in the published tree, which the boundary
# guard fails on and which invariant 7d exists to prevent. Generating them keeps
# the bytes reproducible from the tracked tree without putting them in it: this
# script IS the fixture, and it is reviewable as one.
#
# Each fixture is three files. `target.c` holds the subject and its control in
# one translation unit, so that "the property was removed" cannot be confused
# with "the extractor stopped recognising the property at this optimisation
# level" -- those two produce the same number when only the subject is looked
# at. `opaque.c` holds the producer and consumer, in a second unit, which is
# what forces the buffer to be materialised in memory and keeps a promotion pass
# from being the explanation for anything the subject does. `main.c` links them.
set -u

LAB=${IRCK_LAB:-$HOME/vg-lab/llvm-pass}
FX="$LAB/fixtures"

mkdir -p "$FX"

mkdir -p "$FX/erasure"
cat > "$FX/erasure/main.c" <<'FIXTURE_EOF'
void handle_request(void);
void wipe_kept(void);

int main(void) {
    handle_request();
    wipe_kept();
    return 0;
}
FIXTURE_EOF
cat > "$FX/erasure/opaque.c" <<'FIXTURE_EOF'
/* Producer and consumer in a separate translation unit: this is what forces the
 * secret to be materialised on the stack, and what keeps a promotion pass from
 * being the explanation for anything that happens to the subject. */

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
 *
 * The subject and the control are in the same translation unit on purpose. A
 * measurement that only looks at the subject cannot tell "the wipe was removed"
 * from "the extractor stopped recognising wipes at this optimisation level",
 * and those two produce the same number. */

#include <string.h>

/* Defined in opaque.c, so within this unit the compiler knows nothing about
 * them and the buffer has to be materialised in memory. */
void get_secret(unsigned char *out, unsigned long n);
void consume(const unsigned char *p, unsigned long n);

/* Subject. The wipe is the last use of the buffer, so it is a dead store and
 * the optimiser is free to delete it. The buffer itself is not free to
 * disappear: its address reaches two functions in another unit. */
void handle_request(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    consume(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
}

/* Control. The wipe is read afterwards, so it is observable and cannot be
 * deleted at any optimisation level. Its job is to show that the oracle can
 * still see a wipe in whatever form this configuration chose for it. */
void wipe_kept(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
    consume(secret, sizeof secret);
}

/* Not a control. This function exists to be named as one, in the positive
 * control for the control check itself: its wipe is removable, so pointing
 * OBS_CONTROL_FN at it produces a run in which the control's count also falls
 * to zero. interfaces.md section 4 calls that a broken measurement, and the
 * only way to know the checker agrees is to hand it one. */
void wipe_removable_not_a_control(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    consume(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
}
FIXTURE_EOF

mkdir -p "$FX/authz"
cat > "$FX/authz/main.c" <<'FIXTURE_EOF'
void serve(int uid);
void serve_folded(int uid);
void serve_control(int uid);

int main(void) {
    serve(1);
    serve_folded(2);
    serve_control(3);
    return 0;
}
FIXTURE_EOF
cat > "$FX/authz/opaque.c" <<'FIXTURE_EOF'
volatile int sink;

int is_authorized(int uid) { return (uid & 1) == 0; }

void deny_and_abort(void) { sink = -1; }

void do_work(int uid) { sink += uid; }
FIXTURE_EOF
cat > "$FX/authz/target.c" <<'FIXTURE_EOF'
/* Fail-closed branch: the guard is the property, and the call it guards is how
 * the guard is counted.
 *
 * The extractor for this class refuses to count a guarded call while no
 * conditional branch in the unit still tests a value. A branch on a constant
 * decides nothing, so the deny path it leads to is waiting to be swept up
 * rather than protecting anything -- and a counter that did not know this would
 * report the check as present right up until some later pass removed the block,
 * and then blame that pass. */

/* opaque.c: outside this unit, so nothing here can be folded. */
int is_authorized(int uid);
void deny_and_abort(void);
void do_work(int uid);

/* Subject A: the guard survives, because the condition comes from another
 * unit. */
void serve(int uid) {
    if (!is_authorized(uid)) deny_and_abort();
    do_work(uid);
}

/* Subject B: the same shape, but the condition is decidable at compile time.
 * The optimiser folds the branch and deletes the deny path -- the check is
 * really gone, the unit is still here, and nothing was promoted out of memory.
 * LOST. */
static int build_allows_everything(void) { return 1; }

void serve_folded(int uid) {
    if (!build_allows_everything()) deny_and_abort();
    do_work(uid);
}

/* Control: a deny path behind a condition the compiler cannot resolve and a
 * call it cannot remove. */
void serve_control(int uid) {
    if (!is_authorized(uid)) deny_and_abort();
    do_work(uid + 1);
}
FIXTURE_EOF

mkdir -p "$FX/promotion"
cat > "$FX/promotion/main.c" <<'FIXTURE_EOF'
struct token { unsigned long lo, hi; };

void use_token(unsigned long seed);
void wipe_out(struct token *t);

int main(void) {
    struct token t = { 1ul, 2ul };
    use_token(3ul);
    wipe_out(&t);
    return (int)(t.lo ^ t.hi);
}
FIXTURE_EOF
cat > "$FX/promotion/opaque.c" <<'FIXTURE_EOF'
struct token { unsigned long lo, hi; };

volatile unsigned long sink;

unsigned long derive(unsigned long seed) { return seed * 6364136223846793005ul + 1442695040888963407ul; }

void sink_value(unsigned long v) { sink ^= v; }

void observe_token(const struct token *t) { sink ^= t->lo + t->hi; }
FIXTURE_EOF
cat > "$FX/promotion/token.c" <<'FIXTURE_EOF'
/* LOST against NOT_APPLICABLE, from one source file.
 *
 * The two cells of this fixture compile these exact bytes twice, differing only
 * in whether OBS_FIXTURE_ESCAPE is defined. In both cells the wipe's call-site
 * count goes 1 -> 0 between the two checkpoints, so a checker that decides from
 * the count alone must give the same verdict to both. They are not the same
 * situation:
 *
 *   escape off  the token never has its address taken by anything the optimiser
 *               cannot see through, so SROA promotes it to SSA values and the
 *               wipe stops having a buffer to wipe.  NOT_APPLICABLE.
 *   escape on   one call to another translation unit takes the address, so the
 *               object stays in memory, the wipe is a dead store, and it is
 *               deleted.  LOST.
 *
 * llvm.memset on an alloca is splittable, so it is not itself an obstacle to
 * promotion -- which is why the escaping call has to come from somewhere else. */

#include <string.h>

struct token { unsigned long lo, hi; };

/* opaque.c */
unsigned long derive(unsigned long seed);
void sink_value(unsigned long v);
#ifdef OBS_FIXTURE_ESCAPE
void observe_token(const struct token *t);
#endif

/* Subject. */
void use_token(unsigned long seed) {
    struct token t;
    t.lo = derive(seed);
    t.hi = derive(seed + 1u);
#ifdef OBS_FIXTURE_ESCAPE
    observe_token(&t);
#endif
    sink_value(t.lo ^ t.hi);
    memset(&t, 0, sizeof t);
}

/* Control. The zeroing lands in storage the caller owns, so no optimisation
 * level may remove it and no promotion pass may make the question moot. */
void wipe_out(struct token *t) {
    memset(t, 0, sizeof *t);
}
FIXTURE_EOF

mkdir -p "$FX/inlined"
cat > "$FX/inlined/main.c" <<'FIXTURE_EOF'
void entry(unsigned long seed);
void wipe_out(unsigned char *p, unsigned long n);

int main(void) {
    unsigned char scratch[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    entry(11ul);
    wipe_out(scratch, sizeof scratch);
    return scratch[0];
}
FIXTURE_EOF
cat > "$FX/inlined/opaque.c" <<'FIXTURE_EOF'
volatile unsigned char sink;

void fill(unsigned char *out, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) out[i] = (unsigned char)(i * 31u + 5u);
}

void consume(const unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) sink ^= p[i];
}
FIXTURE_EOF
cat > "$FX/inlined/target.c" <<'FIXTURE_EOF'
/* The second reason a question stops having an answer: the unit it was asked
 * about is not there any more.
 *
 * scrub_and_report has internal linkage and exactly one caller, so above -O0 it
 * is inlined and its out-of-line body is deleted. The wipe has not gone
 * anywhere -- explicit_bzero is not removable, and after inlining it sits in
 * entry() -- so a checker that reads "no wipe in scrub_and_report" as a loss is
 * reporting a false positive about a program that still does the thing. The
 * record shows both numbers: the unit's call-site count is 0 and the module's
 * is not, which is the shape this state exists to describe. NOT_APPLICABLE. */

#define _GNU_SOURCE 1
#include <string.h>

/* opaque.c */
void fill(unsigned char *out, unsigned long n);
void consume(const unsigned char *p, unsigned long n);

static void scrub_and_report(unsigned long seed) {
    unsigned char buf[64];
    fill(buf, sizeof buf);
    buf[0] ^= (unsigned char)seed;
    consume(buf, sizeof buf);
    explicit_bzero(buf, sizeof buf);
}

void entry(unsigned long seed) {
    scrub_and_report(seed);
}

/* Control: zeroing through a caller-owned pointer with a run-time length, which
 * nothing in the pipeline may remove or absorb. */
void wipe_out(unsigned char *p, unsigned long n) {
    memset(p, 0, n);
}
FIXTURE_EOF

mkdir -p "$FX/residue"
cat > "$FX/residue/main.c" <<'FIXTURE_EOF'
void handle_request(void);
void wipe_kept(void);

int main(void) {
    handle_request();
    wipe_kept();
    return 0;
}
FIXTURE_EOF
cat > "$FX/residue/opaque.c" <<'FIXTURE_EOF'
volatile unsigned char sink;

void get_secret(unsigned char *out, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) out[i] = (unsigned char)(i * 7u + 1u);
}

void consume(const unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) sink ^= p[i];
}
FIXTURE_EOF
cat > "$FX/residue/target.c" <<'FIXTURE_EOF'
/* Why the oracle resolves callees instead of asking whether a symbol exists.
 *
 * The subject's wipe is the module's only memset call. Once it is deleted the
 * declaration stays behind, so "does this module contain memset" -- the C++
 * spelling of a grep -- keeps answering yes with nothing to point at. The
 * control's wipe is in the same effect family but is spelled with a different
 * symbol and cannot be removed, so the control still holds while the subject's
 * symbol decays to a bare declaration, and the two oracles can be seen giving
 * different answers about the same module in the same run. */

#define _GNU_SOURCE 1
#include <string.h>

/* opaque.c */
void get_secret(unsigned char *out, unsigned long n);
void consume(const unsigned char *p, unsigned long n);

void handle_request(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    consume(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
}

void wipe_kept(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    consume(secret, sizeof secret);
    explicit_bzero(secret, sizeof secret);
}
FIXTURE_EOF

# `inlined-removable` is `inlined` with one word changed, and it exists because
# the difference that word makes is the whole discrimination this component
# claims to perform. `explicit_bzero` cannot be deleted, so when the callee is
# inlined the effect moves into the caller and NOT_APPLICABLE is the true
# answer. `memset` on a dead buffer can be deleted, so the same inlining ends
# with the program not zeroing anything -- and a verdict decided from unit
# presence alone gives both cases the same answer, with the same reason string
# and no findings. It did, until it was measured.
mkdir -p "$FX/inlined-removable"
sed 's/explicit_bzero(buf, sizeof buf);/memset(buf, 0, sizeof buf);/'   "$FX/inlined/target.c" > "$FX/inlined-removable/target.c"
cp "$FX/inlined/opaque.c" "$FX/inlined/main.c" "$FX/inlined-removable/"

# `promotion-decoy` is the promotion fixture with one extra object of the SAME
# SIZE as the subject's, in the same function, escaping so that it survives.
# Only the census of the unit changes; the subject is promoted either way.
mkdir -p "$FX/promotion-decoy"
cp "$FX/promotion/main.c" "$FX/promotion-decoy/main.c"
cat > "$FX/promotion-decoy/token.c" <<'FIXTURE_EOF'
/* A same-sized bystander must not vouch for the subject.
 *
 * This is the promotion fixture with one extra object added to the SUBJECT
 * function: the same size as the token, and escaping, so it survives to the
 * second checkpoint. The subject is still promoted entirely to SSA. A
 * discriminator that asks "is an object of this size still allocated here"
 * answers yes and reports a removed wipe against a function that no longer has
 * a buffer to wipe. Measured: it did, and the verdict read LOST with a
 * VG-PROP-001 finding at high severity.
 *
 * The original header follows, because the rest of the reasoning is unchanged.
 *
 * LOST against NOT_APPLICABLE, from one source file.
 *
 * The two cells of this fixture compile these exact bytes twice, differing only
 * in whether OBS_FIXTURE_ESCAPE is defined. In both cells the wipe's call-site
 * count goes 1 -> 0 between the two checkpoints, so a checker that decides from
 * the count alone must give the same verdict to both. They are not the same
 * situation:
 *
 *   escape off  the token never has its address taken by anything the optimiser
 *               cannot see through, so SROA promotes it to SSA values and the
 *               wipe stops having a buffer to wipe.  NOT_APPLICABLE.
 *   escape on   one call to another translation unit takes the address, so the
 *               object stays in memory, the wipe is a dead store, and it is
 *               deleted.  LOST.
 *
 * llvm.memset on an alloca is splittable, so it is not itself an obstacle to
 * promotion -- which is why the escaping call has to come from somewhere else. */

#include <string.h>

struct token { unsigned long lo, hi; };

/* opaque.c */
unsigned long derive(unsigned long seed);
void sink_value(unsigned long v);
void observe_unrelated(const struct token *t);
#ifdef OBS_FIXTURE_ESCAPE
void observe_token(const struct token *t);
#endif

/* Subject. */
void use_token(unsigned long seed) {
    struct token t;
    t.lo = derive(seed);
    t.hi = derive(seed + 1u);
#ifdef OBS_FIXTURE_ESCAPE
    observe_token(&t);
#endif
    struct token unrelated;
    unrelated.lo = seed; unrelated.hi = seed + 2u;
    observe_unrelated(&unrelated);
    sink_value(t.lo ^ t.hi);
    memset(&t, 0, sizeof t);
}

/* Control. The zeroing lands in storage the caller owns, so no optimisation
 * level may remove it and no promotion pass may make the question moot. */
void wipe_out(struct token *t) {
    memset(t, 0, sizeof *t);
}
FIXTURE_EOF
cat > "$FX/promotion-decoy/opaque.c" <<'FIXTURE_EOF'
struct token { unsigned long lo, hi; };

volatile unsigned long sink;

unsigned long derive(unsigned long seed) { return seed * 6364136223846793005ul + 1442695040888963407ul; }

void sink_value(unsigned long v) { sink ^= v; }

void observe_token(const struct token *t) { sink ^= t->lo + t->hi; }

void observe_unrelated(const struct token *t) { sink ^= t->lo - t->hi; }
FIXTURE_EOF

echo "fixtures written to $FX"
