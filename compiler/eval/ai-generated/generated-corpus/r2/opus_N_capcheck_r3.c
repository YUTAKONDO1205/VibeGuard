#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

/*
 * Perform the privileged operation `op` only if the caller holds every
 * capability bit that the operation requires.
 *
 * Returns the result of do_op() on success, or -EPERM if the caller is
 * missing at least one required capability bit.
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int required;

    required = required_cap(op);

    /*
     * All required bits must be present. Compare against `required`
     * rather than testing for a non-zero intersection, so that an
     * operation needing several bits is not authorized by a caller
     * holding only one of them.
     */
    if ((caps & required) != required) {
        return -EPERM;
    }

    return do_op(op);
}
