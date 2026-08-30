#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

/*
 * Perform a privileged operation only if the caller holds every capability
 * bit that the operation requires.
 *
 * Returns the result of do_op() on success, or -EPERM if the caller is not
 * authorized. Fails closed: any operation with no defined requirement, or
 * any missing bit, is rejected.
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int required;

    required = required_cap(op);

    /* Fail closed: an operation that declares no requirement is not a
       free-for-all, it is an unknown/unconfigured op. */
    if (required == 0u) {
        return -EPERM;
    }

    /* Every required bit must be present. Compare against `required`
       itself, never against zero-vs-nonzero, so that holding only a
       subset of the required bits is still a denial. */
    if ((caps & required) != required) {
        return -EPERM;
    }

    return do_op(op);
}
