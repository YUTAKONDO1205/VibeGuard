#!/bin/bash
# The one measurement input the configuration envelope needs and the optimisation
# matrix does not have: a fail-closed check that -DNDEBUG deletes.
#
#   bash compiler/llvm-pass/scripts/envelope-fixtures.sh
#   IRCK_LAB=/somewhere bash compiler/llvm-pass/scripts/envelope-fixtures.sh
#
# Same rule as tools/make-fixtures.sh, and for the same reason: the fixture is
# written into the lab, never under compiler/, because a measurement input in the
# published tree is a boundary violation. This script IS the fixture and is
# reviewable as one. It only adds; it never touches what make-fixtures.sh wrote,
# so both can be run into the same lab in either order.
#
# Placement note: this belongs beside make-fixtures.sh in tools/. It is in
# scripts/ because the change that added it was scoped to scripts/, and moving it
# is a one-line follow-up rather than a rewrite.
set -u

LAB=${IRCK_LAB:-$HOME/vg-lab/llvm-pass}
FX="$LAB/fixtures"

mkdir -p "$FX/ndebug"

cat > "$FX/ndebug/main.c" <<'FIXTURE_EOF'
void serve_asserted(int uid);
void serve_control(int uid);

int main(void) {
    serve_asserted(1);
    serve_control(2);
    return 0;
}
FIXTURE_EOF

cat > "$FX/ndebug/opaque.c" <<'FIXTURE_EOF'
volatile int sink;

int is_authorized(int uid) { return (uid & 1) == 0; }

void deny_and_abort(void) { sink = -1; }

void do_work(int uid) { sink += uid; }
FIXTURE_EOF

cat > "$FX/ndebug/target.c" <<'FIXTURE_EOF'
/* A fail-closed check that no optimisation level can remove and one -D deletes.
 *
 * Every other fixture in this lab varies the optimiser. This one varies the
 * configuration, because the two are not the same axis and a matrix that only
 * has the first cannot see the second. The subject's check is spelled the way a
 * great deal of C spells a security check -- as an assertion the release build
 * turns off. When NDEBUG is defined the check is gone before any IR exists, so
 * there is no pass to attribute it to and no optimisation level at which it
 * survives; the property is simply not in the build.
 *
 * The control's deny path is not behind the macro. That is what makes the
 * subject's disappearance readable: without it, "the check vanished" and "the
 * extractor stopped counting deny paths in this configuration" produce the same
 * number, and only one of them is about the program. */

/* opaque.c: outside this unit, so nothing here can be folded. */
int is_authorized(int uid);
void deny_and_abort(void);
void do_work(int uid);

#ifdef NDEBUG
#  define REQUIRE(cond) ((void)0)
#else
#  define REQUIRE(cond) do { if (!(cond)) deny_and_abort(); } while (0)
#endif

/* Subject. With NDEBUG undefined this is the same shape as authz/serve: a
 * condition the compiler cannot resolve guarding a call it cannot remove, so it
 * survives every optimisation level. With NDEBUG defined the body is
 * do_work(uid) and nothing else. */
void serve_asserted(int uid) {
    REQUIRE(is_authorized(uid));
    do_work(uid);
}

/* Control: the same deny path, unconditionally compiled. */
void serve_control(int uid) {
    if (!is_authorized(uid)) deny_and_abort();
    do_work(uid + 1);
}
FIXTURE_EOF

echo "envelope fixtures written to ${FX#"$HOME/"}"
