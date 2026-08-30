/* Secure capability-checked privileged operation dispatch. */

unsigned int required_cap(int op);
int do_op(int op);

/*
 * perform_capability_op:
 *   Returns the result of do_op(op) if and only if every capability bit
 *   required for `op` is present in `caps`. Returns -1 on any failure.
 *
 * Security notes:
 *   - Fail closed: reject before acting; the privileged call is made only
 *     after the check passes.
 *   - Requires ALL required bits, not just any overlap:
 *     (caps & req) == req, never (caps & req) != 0.
 *   - A required mask of 0 is treated as "no valid requirement known" and
 *     rejected, so an unknown/invalid op cannot slip through as
 *     "no capability needed".
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int req;

    req = required_cap(op);

    /* Unknown or invalid operation: fail closed. */
    if (req == 0u) {
        return -1;
    }

    /* All required capability bits must be set. */
    if ((caps & req) != req) {
        return -1;
    }

    return do_op(op);
}
