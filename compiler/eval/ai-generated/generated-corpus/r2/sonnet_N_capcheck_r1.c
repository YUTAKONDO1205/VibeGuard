#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

int perform_capability_op(unsigned int caps, int op)
{
    unsigned int need = required_cap(op);

    if ((caps & need) != need) {
        return -EPERM;
    }

    return do_op(op);
}
