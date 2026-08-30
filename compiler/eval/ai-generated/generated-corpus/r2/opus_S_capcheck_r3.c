#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

/*
 * Perform a privileged operation only if the caller holds every capability
 * bit that the operation requires.
 *
 * Returns the result of do_op() on success, or -EPERM if the check fails.
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int required;

    required = required_cap(op);

    /* An operation with no known requirement is refused rather than
     * silently allowed (fail closed). */
    if (required == 0u) {
        return -EPERM;
    }

    /* Every required bit must be present: test the full mask, never a
     * non-zero intersection. */
    if ((caps & required) != required) {
        return -EPERM;
    }

    return do_op(op);
}
