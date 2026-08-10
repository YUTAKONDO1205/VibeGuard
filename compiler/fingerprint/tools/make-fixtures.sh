#!/usr/bin/env bash
# Generate the real IR the fingerprint is measured on.
#
#   bash make-fixtures.sh [scratch-dir]
#
# Writes fixture.c into <scratch>/src and one .ll per optimisation level into
# <scratch>/ir, named <fixture>.O<n>.ll. Nothing here writes inside the
# repository: the IR is measurement input, not source.
#
# The fixture carries a SUBJECT whose wipe is dead (an optimiser is entitled to
# delete it) and a CONTROL whose wipe cannot be deleted at any level, because
# the buffer escapes afterwards to a function the compiler cannot see. Every
# measurement in this package is read against that control: if the control's
# effect count reaches zero the oracle stopped working and the run reports an
# incomplete check rather than a finding. See compiler/schema/interfaces.md
# section 4.
set -eu

SCRATCH="${1:-$HOME/vg-lab/fingerprint}"
CC="${CC:-clang-18}"

if ! command -v "$CC" >/dev/null 2>&1; then
  echo "make-fixtures: $CC not found" >&2
  echo "inputs=0 checked=0 skipped=0" >&2
  exit 3
fi

SRC="$SCRATCH/src"
IR="$SCRATCH/ir"
mkdir -p "$SRC" "$IR"

cat > "$SRC/fixture.c" <<'EOF'
/* Fixture for the general property fingerprint.
 *
 * subject_wipe : the wipe is dead. Nothing reads the buffer afterwards, so an
 *                optimiser may delete the call. This is the thing being
 *                measured.
 * control_wipe : the wipe is followed by an escape to a function whose body
 *                the compiler cannot see, so the call cannot be deleted at any
 *                level. This is the control. A measurement where its effect
 *                count reaches zero is a broken measurement.
 * control_pure : a small arithmetic control with no memory traffic once the
 *                allocas are promoted. It exists to separate "the fingerprint
 *                is unstable because the function is complicated" from "the
 *                fingerprint is unstable for everything".
 * subject_branch / control_branch : a fail-closed branch pair, so the
 *                measurement is not a single property class.
 */
#include <stddef.h>
#include <string.h>

/* Defined in another translation unit on purpose: opaque to the optimiser. */
extern void control_observe(const unsigned char *p, size_t n);
extern int  control_decide(int v);

int subject_wipe(const unsigned char *in, size_t n)
{
    unsigned char key[32];
    size_t i;
    int acc = 0;

    for (i = 0; i < 32; i++)
        key[i] = (i < n) ? in[i] : 0;
    for (i = 0; i < 32; i++)
        acc += key[i];

    memset(key, 0, sizeof key);   /* dead: nothing reads key after this */
    return acc;
}

int control_wipe(const unsigned char *in, size_t n)
{
    unsigned char buf[32];
    size_t i;
    int acc = 0;

    for (i = 0; i < 32; i++)
        buf[i] = (i < n) ? in[i] : 0;
    for (i = 0; i < 32; i++)
        acc += buf[i];

    memset(buf, 0, sizeof buf);
    control_observe(buf, sizeof buf);   /* the wipe's effect escapes here */
    return acc;
}

int control_pure(int a, int b)
{
    int s = a + b;
    int t = b * 3;
    return s ^ t;
}

int subject_branch(int v)
{
    /* The guard is redundant with the callee's own check, so an optimiser is
     * allowed to fold it away. */
    if (v > 0)
        return control_decide(v);
    return 0;
}

int control_branch(int v)
{
    /* The guard tests a value the compiler cannot know, so it survives. */
    if (control_decide(v) != 0)
        return 1;
    return 0;
}
EOF

# ── Variants, so the real-IR measurement has both directions ────────────────
#
# renamed/  identical program, every local renamed and the file in a different
#           directory. The fingerprint MUST NOT change: this is the real-IR
#           perturbation for `ssa-values` and `debug-paths` together.
# nowipe/   identical program with the control's wipe deleted. The fingerprint
#           MUST change: without this, the line above is satisfied by any
#           constant.
mkdir -p "$SRC/renamed" "$SRC/nowipe"

sed -e 's/\bkey\b/secret_material/g' \
    -e 's/\bbuf\b/scratch_area/g' \
    -e 's/\bacc\b/running_total/g' \
    -e 's/\bi\b/idx/g' \
    -e 's/\bv\b/incoming/g' \
    -e 's/\ba\b/lhs/g' \
    -e 's/\bb\b/rhs/g' \
    -e 's/\bs\b/sum_value/g' \
    -e 's/\bt\b/tripled/g' \
    -e 's/\bn\b/count/g' \
    "$SRC/fixture.c" > "$SRC/renamed/fixture.c"

sed -e '/memset(buf, 0, sizeof buf);/d' "$SRC/fixture.c" > "$SRC/nowipe/fixture.c"

LEVELS="0 1 2 3"
n=0
for O in $LEVELS; do
  "$CC" -S -emit-llvm -g  -O"$O" -o "$IR/fixture.O$O.ll"         "$SRC/fixture.c"
  "$CC" -S -emit-llvm     -O"$O" -o "$IR/fixture-nodbg.O$O.ll"   "$SRC/fixture.c"
  "$CC" -S -emit-llvm -g  -O"$O" -o "$IR/fixture-renamed.O$O.ll" "$SRC/renamed/fixture.c"
  "$CC" -S -emit-llvm -g  -O"$O" -o "$IR/fixture-nowipe.O$O.ll"  "$SRC/nowipe/fixture.c"
  n=$((n + 4))
done

echo "wrote $n IR files to $IR"
echo "inputs=$n checked=$n skipped=0"
