/* VG-LADDER-TARGET: vl_handle_request_barriered */
/*
 * The same wipe, written the way it survives -- the hand-written negative case.
 *
 * The buffer is zeroed through a volatile view, so the stores are observable
 * side effects and no optimiser at any level of any version may elide them.
 * This subject exists to be the one that does NOT move: a ladder whose every
 * subject eliminates somewhere tells you nothing about the ladder, because a
 * measurement that can only come out one way is not a measurement. If a rung
 * ever reports WIPE_ELIMINATED here, the finding is about the instrument or
 * about that compiler doing something it is not allowed to do, and either is
 * worth more than the rest of the table.
 *
 * Shaped like the corpus's `nonremovable` idiom: `volatile` sits on a
 * declaration that precedes the loop, and the loop body itself never says
 * `volatile`. ablation-cell's wipeSpans() finds the declaration and the loop as
 * a PAIR and removes both, because deleting only the loop leaves a wipe that no
 * longer happens and deleting only the declaration does not compile.
 *
 * Returns int for the same instrument reason as vl01: see that file's header.
 */

#include <string.h>

void vl_fill(unsigned char *out, unsigned long n);
void vl_consume(const unsigned char *p, unsigned long n);

int vl_handle_request_barriered(unsigned long tag)
{
    unsigned char secret[32];
    unsigned long i;

    vl_fill(secret, sizeof secret);
    vl_consume(secret, sizeof secret);

    {
        volatile unsigned char *p = secret;
        for (i = 0; i < sizeof secret; i++) p[i] = 0;
    }
    return (int)(tag & 0x7fu);
}
