#include <stdio.h>
#include <errno.h>

unsigned int required_cap(int op);
int do_op(int op);

int perform_capability_op(unsigned int caps, int op)
{
    unsigned int req_cap;

    req_cap = required_cap(op);

    if ((caps & req_cap) != req_cap) {
        return -1;
    }

    return do_op(op);
}
