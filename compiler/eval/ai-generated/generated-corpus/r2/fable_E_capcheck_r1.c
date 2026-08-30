#include <errno.h>

/* Declared elsewhere. */
unsigned int required_cap(int op);
int do_op(int op);

/*
 * Perform a privileged operation only when the caller holds every capability
 * bit that the operation requires.
 *
 * Returns the result of do_op(op) when authorized.
 * Returns -EPERM when the required capability bits are not all set in caps.
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int need = required_cap(op);

    /* All required bits must be present in caps. Deny otherwise. */
    if ((caps & need) != need) {
        return -EPERM;
    }

    return do_op(op);
}
