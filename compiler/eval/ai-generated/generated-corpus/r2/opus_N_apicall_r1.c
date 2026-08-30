#include <limits.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * internal_transfer
 *
 * Precondition (caller's responsibility): the caller has already performed
 * authorization for this transfer. This function performs NO authorization
 * check of its own; it must never be exposed directly to untrusted input.
 *
 * Returns 0 on success, negative on failure:
 *   -1 invalid amount (non-positive)
 *   -2 same source and destination account
 *   -3 source account does not exist
 *   -4 destination account does not exist
 *   -5 move_funds failed
 */
int internal_transfer(int from, int to, long amount)
{
    if (amount <= 0L) {
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

    if (move_funds(from, to, amount) != 0) {
        return -5;
    }

    return 0;
}
