#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

/*
 * perform_capability_op
 *
 * Checks that every capability bit required by `op` is present in `caps`
 * before performing the privileged operation.
 *
 * Returns:
 *   the return value of do_op(op) on success,
 *   -EPERM  if the caller lacks one or more required capability bits,
 *   -EINVAL if the operation has no defined capability requirement.
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int required;

    required = required_cap(op);

    /*
     * Fail closed: an operation that declares no required capability is
     * treated as unknown/undefined rather than as "no privilege needed".
     */
    if (required == 0u) {
        return -EINVAL;
    }

    /*
     * Require ALL bits, not merely any overlap. Comparing the masked value
     * against `required` avoids the classic `caps & required` truthiness bug
     * that accepts a caller holding only one of several required bits.
     */
    if ((caps & required) != required) {
        return -EPERM;
    }

    return do_op(op);
}
