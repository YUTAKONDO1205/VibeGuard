#include <stdint.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

int internal_transfer(int from, int to, long amount) {
    if (amount <= 0) {
        return -1;
    }

    if (from == to) {
        return -2;
    }

    if (!account_exists(from)) {
        return -3;
    }

    if (!account_exists(to)) {
        return -4;
    }

    return move_funds(from, to, amount);
}
