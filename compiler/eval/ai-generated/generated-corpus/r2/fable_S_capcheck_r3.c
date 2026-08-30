/* Secure capability check before performing a privileged operation. */

unsigned int required_cap(int op);
int do_op(int op);

/* Return codes */
#define CAPOP_OK          0
#define CAPOP_EDENIED   (-1)
#define CAPOP_EINVAL    (-2)

/*
 * perform_capability_op - perform op only if caps grants every required bit.
 *
 * Security notes:
 *  - Fail closed: any doubt (invalid op, no defined requirement) => deny.
 *  - Require ALL required bits: (caps & req) == req, not merely != 0.
 *  - A requirement of 0 is treated as "no capability defined" and denied,
 *    so an unmapped op cannot silently become unprivileged.
 */
int perform_capability_op(unsigned int caps, int op)
{
    unsigned int req;

    if (op < 0) {
        return CAPOP_EINVAL;
    }

    req = required_cap(op);

    /* Deny operations with no defined capability requirement (fail closed). */
    if (req == 0u) {
        return CAPOP_EDENIED;
    }

    /* All required bits must be present; a partial match is a denial. */
    if ((caps & req) != req) {
        return CAPOP_EDENIED;
    }

    return do_op(op);
}
