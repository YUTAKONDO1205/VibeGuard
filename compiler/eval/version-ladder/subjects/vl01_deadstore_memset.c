/* VG-LADDER-TARGET: vl_handle_request */
/*
 * A wipe the optimiser is entitled to delete, written by hand.
 *
 * Every other subject this lane measures was written by a language model, which
 * makes the whole lane's input one distribution. This file and its sibling are
 * the two rungs of the ladder that are not: if a first appearance is a fact
 * about compiler versions it must show here too, and if it only shows on
 * generated code that is itself the finding.
 *
 * The producer and the consumer are declared and not defined, so within this
 * translation unit the compiler knows nothing about them and the buffer has to
 * be materialised in memory. That is what keeps a promotion pass from being the
 * explanation for anything the subject does. The unit compiles to assembly on
 * its own (-S), which is all the lane's instrument asks of it; it does not link,
 * and it is not meant to.
 *
 * The target returns int rather than void on purpose, and the reason is
 * unfortunately about the instrument rather than about C. ablation-cell's
 * wipeHelpers() classifies any `void f(...)` whose body contains a memset as a
 * wipe helper, and wipeSpans() then matches that helper's name followed by
 * `(...);`, which a void target's own DEFINITION header satisfies. See the
 * README, "The hand-written llvm-pass fixture does not score" -- that is exactly
 * what happens to compiler/llvm-pass/tools/make-fixtures.sh's target.c here.
 */

#include <string.h>

void vl_fill(unsigned char *out, unsigned long n);
void vl_consume(const unsigned char *p, unsigned long n);

int vl_handle_request(unsigned long tag)
{
    unsigned char secret[32];

    vl_fill(secret, sizeof secret);
    vl_consume(secret, sizeof secret);
    /* The last use of the buffer. A dead store, and the optimiser is free to
     * delete it -- which is the whole subject of the measurement. */
    memset(secret, 0, sizeof secret);
    return (int)(tag & 0x7fu);
}
