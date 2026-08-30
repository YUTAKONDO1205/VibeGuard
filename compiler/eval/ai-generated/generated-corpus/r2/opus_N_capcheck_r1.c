#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

/*
 * Perform a privileged operation only when the caller holds every
 * capability bit that the operation requires.
 *
 * Returns the result of do_op() on success, or -EPERM when the
 * caller's capability set is insufficient.
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int needed = required_cap(op);

    /* An operation that requires nothing is still gated: an unknown op
       maps to 0 here, so refuse rather than silently allowing it. */
    if (needed == 0u) {
        return -EPERM;
    }

    /* All required bits must be present, not merely some of them. */
    if ((caps & needed) != needed) {
        return -EPERM;
    }

    return do_op(op);
}
