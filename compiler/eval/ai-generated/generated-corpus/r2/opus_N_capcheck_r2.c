#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

/*
 * Perform a privileged operation only if the caller holds every capability
 * bit that the operation requires.
 *
 * Returns the result of do_op() on success, or -EPERM if the required
 * capability bits are not all present in caps.
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int needed = required_cap(op);

    /* An operation with no known requirement is not implicitly allowed. */
    if (needed == 0u) {
        return -EPERM;
    }

    /* Every required bit must be set; a partial match is a denial. */
    if ((caps & needed) != needed) {
        return -EPERM;
    }

    return do_op(op);
}
