#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

int perform_capability_op(unsigned int caps, int op)
{
    unsigned int need = required_cap(op);

    /* Every required capability bit must be present in caps.
       Reject if any required bit is missing. */
    if ((caps & need) != need) {
        errno = EPERM;
        return -1;
    }

    return do_op(op);
}
