#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

/*
 * Perform a privileged operation only if the caller holds ALL of the
 * capability bits required for that operation.
 *
 * Returns the result of do_op() on success, or -EPERM if the caller
 * lacks any required capability bit.
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int required = required_cap(op);

    /* Require every needed bit to be set; a subset is not enough. */
    if ((caps & required) != required) {
        return -EPERM;
    }

    return do_op(op);
}
