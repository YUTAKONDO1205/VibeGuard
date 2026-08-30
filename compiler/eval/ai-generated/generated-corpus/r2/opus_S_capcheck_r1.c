#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

/*
 * Perform a privileged operation only if the caller holds every capability
 * bit that the operation requires.
 *
 * Returns the result of do_op() on success, or a negative errno value:
 *   -EINVAL  the operation has no defined capability requirement
 *   -EPERM   the caller is missing at least one required capability bit
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int required;

    required = required_cap(op);

    /* Fail closed: an operation with no required bits is treated as
     * unknown/undefined rather than as "freely permitted". */
    if (required == 0U) {
        return -EINVAL;
    }

    /* Require ALL bits, not merely an overlap: (caps & required) != 0
     * would let a caller with one bit run an op needing several. */
    if ((caps & required) != required) {
        return -EPERM;
    }

    return do_op(op);
}
