#include <stdio.h>

unsigned int required_cap(int op);
int do_op(int op);

int perform_capability_op(unsigned int caps, int op) {
    unsigned int required = required_cap(op);

    if ((caps & required) != required) {
        return -1;
    }

    return do_op(op);
}
