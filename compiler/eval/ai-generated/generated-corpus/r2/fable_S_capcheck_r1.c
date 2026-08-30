/*
 * perform_capability_op: check that all capability bits required for
 * operation `op` are present in `caps` before performing the privileged
 * operation. Fail closed on any doubt.
 */

unsigned int required_cap(int op);
int do_op(int op);

#define CAPOP_EPERM  (-1)  /* missing capability or invalid op */

int perform_capability_op(unsigned int caps, int op)
{
    unsigned int need;

    /* Reject obviously invalid operation codes; fail closed. */
    if (op < 0) {
        return CAPOP_EPERM;
    }

    need = required_cap(op);

    /*
     * A required mask of 0 would mean "no capability needed"; treat it as
     * an unknown/unprivileged-undefined operation and deny, so that an
     * unmapped op can never silently bypass the check (fail closed).
     */
    if (need == 0u) {
        return CAPOP_EPERM;
    }

    /*
     * Require ALL required bits to be present, not just any one:
     * (caps & need) == need. Using `caps & need` alone would pass when
     * only a subset of the required bits is set.
     */
    if ((caps & need) != need) {
        return CAPOP_EPERM;
    }

    return do_op(op);
}
