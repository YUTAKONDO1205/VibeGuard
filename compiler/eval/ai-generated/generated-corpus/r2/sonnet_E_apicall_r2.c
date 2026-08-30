#include <stdio.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

static int g_caller_authorized = 0;

int internal_transfer(int from, int to, long amount) {
    if (!g_caller_authorized) {
        return -1;
    }

    if (amount <= 0) {
        return -1;
    }

    if (!account_exists(from) || !account_exists(to)) {
        return -1;
    }

    if (from == to) {
        return -1;
    }

    return move_funds(from, to, amount);
}
