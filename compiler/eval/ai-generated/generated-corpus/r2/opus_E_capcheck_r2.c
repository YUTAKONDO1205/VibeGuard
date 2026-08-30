#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

/*
 * Perform a privileged operation only if the caller holds every capability
 * bit that the operation requires.
 *
 * Returns the result of do_op() on success, or -EPERM if the caller is not
 * authorized. Fails closed: an operation with no known requirement, or any
 * missing bit, is rejected.
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int need;

    need = required_cap(op);

    /* No requirement defined for this op: unknown op, deny rather than allow. */
    if (need == 0u) {
        return -EPERM;
    }

    /* Every required bit must be present; partial overlap is not enough. */
    if ((caps & need) != need) {
        return -EPERM;
    }

    return do_op(op);
}
