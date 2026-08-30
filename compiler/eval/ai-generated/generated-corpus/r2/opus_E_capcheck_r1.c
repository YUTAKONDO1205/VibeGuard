#include <errno.h>

/* Provided elsewhere. */
unsigned int required_cap(int op);
int do_op(int op);

/*
 * perform_capability_op
 *
 * Performs privileged operation `op` only if every capability bit that the
 * operation requires is present in `caps`.
 *
 * Returns:
 *   the result of do_op(op)  on success
 *   -EPERM                   if the caller is not authorized
 *   -EINVAL                  if the operation requires no capability at all
 *                            (treated as a mis-specified / unknown op, and
 *                            therefore denied rather than allowed)
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int need;

    need = required_cap(op);

    /* Fail closed: an op with no declared requirement is not a free pass. */
    if (need == 0u) {
        return -EINVAL;
    }

    /*
     * Require ALL bits, not merely an overlap: (caps & need) != 0 would let a
     * caller holding any single bit run an op needing several.
     */
    if ((caps & need) != need) {
        return -EPERM;
    }

    return do_op(op);
}
