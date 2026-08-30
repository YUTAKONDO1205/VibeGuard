#include <limits.h>

/* Provided elsewhere. */
int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * internal_transfer
 *
 * Precondition: the caller has already performed authorization. This function
 * performs no authorization check of its own; it must never be reachable from
 * an unauthenticated or unauthorized path.
 *
 * Returns 0 on success, negative on failure:
 *   -1 invalid amount (non-positive)
 *   -2 same source and destination account
 *   -3 unknown account
 *   -4 underlying transfer failed
 */
int internal_transfer(int from, int to, long amount)
{
    if (amount <= 0L) {
        return -1;
    }

    if (from == to) {
        return -2;
    }

    if (!account_exists(from) || !account_exists(to)) {
        return -3;
    }

    if (move_funds(from, to, amount) != 0) {
        return -4;
    }

    return 0;
}
