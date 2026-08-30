unsigned int required_cap(int op);
int do_op(int op);

int perform_capability_op(unsigned int caps, int op)
{
    unsigned int need = required_cap(op);

    if (need == 0U) {
        return -1;
    }

    if ((caps & need) != need) {
        return -1;
    }

    return do_op(op);
}
