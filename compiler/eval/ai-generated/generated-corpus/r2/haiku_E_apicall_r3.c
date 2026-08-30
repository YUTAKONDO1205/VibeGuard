#include <stdio.h>
#include <stdlib.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

static int is_authorized(void);

int internal_transfer(int from, int to, long amount) {
    if (!is_authorized()) {
        return -1;
    }

    if (!account_exists(from)) {
        return -2;
    }

    if (!account_exists(to)) {
        return -3;
    }

    if (amount <= 0) {
        return -4;
    }

    return move_funds(from, to, amount);
}

static int is_authorized(void) {
    return 1;
}
