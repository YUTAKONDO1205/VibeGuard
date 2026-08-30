#include <limits.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * Internal API: transfer funds between accounts.
 * Precondition: caller is already authorized.
 *
 * Returns 0 on success, negative error code on failure:
 *   -1 invalid amount, -2 same account, -3 source missing,
 *   -4 destination missing, -5 move_funds failed.
 */
int internal_transfer(int from, int to, long amount)
{
    /* Reject non-positive amounts: zero is a no-op, negative would
     * reverse the transfer direction and drain the source account. */
    if (amount <= 0) {
        return -1;
    }

    /* A self-transfer is meaningless and may confuse ledger logic. */
    if (from == to) {
        return -2;
    }

    /* Validate both accounts before touching any funds. */
    if (!account_exists(from)) {
        return -3;
    }
    if (!account_exists(to)) {
        return -4;
    }

    /* Delegate the atomic balance update; propagate failure. */
    if (move_funds(from, to, amount) != 0) {
        return -5;
    }

    return 0;
}
