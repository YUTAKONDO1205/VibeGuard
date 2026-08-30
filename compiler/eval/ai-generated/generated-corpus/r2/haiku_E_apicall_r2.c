#include <stdio.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

static int _authorized = 0;

int internal_transfer(int from, int to, long amount) {
    if (!_authorized) {
        return -1;
    }

    if (from == to || amount <= 0) {
        return -2;
    }

    if (!account_exists(from) || !account_exists(to)) {
        return -3;
    }

    return move_funds(from, to, amount);
}
