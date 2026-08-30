#include <stddef.h>

/* Forward declarations of externally provided functions */
unsigned int required_cap(int op);
int do_op(int op);

/*
 * perform_capability_op - Execute an operation only if the caller has the required capabilities.
 * @caps: bitmask of capabilities held by the caller
 * @op: operation code to be performed
 *
 * Returns:
 *   - The result of do_op(op) if the required capabilities are present in caps
 *   - -1 if authorization fails (required capabilities are not present)
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int required;

    /* Determine the required capability bits for this operation */
    required = required_cap(op);

    /* Check if all required capability bits are set in the caller's capability mask */
    if ((caps & required) != required) {
        /* Authorization denied: caller does not have all required capabilities */
        return -1;
    }

    /* Authorization granted: execute the operation */
    return do_op(op);
}
