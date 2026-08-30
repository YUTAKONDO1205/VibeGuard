/* perform_capability_op: check capability bits before a privileged operation. */

unsigned int required_cap(int op);
int do_op(int op);

/*
 * Returns the result of do_op(op) if the caller holds every required
 * capability bit; returns -1 (denied) otherwise.
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int need = required_cap(op);

    /* Deny unknown/invalid operations: a zero requirement mask means
     * required_cap() could not map this op to a capability, so refuse
     * rather than default-allow. */
    if (need == 0u) {
        return -1;
    }

    /* Every required bit must be set in caps (subset test, not any-bit). */
    if ((caps & need) != need) {
        return -1;
    }

    return do_op(op);
}
