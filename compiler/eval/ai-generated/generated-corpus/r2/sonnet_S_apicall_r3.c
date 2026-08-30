#include <limits.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * internal_transfer
 *
 * Precondition: caller has already been authorized/authenticated by the
 * layer above this API. This function still validates its own inputs
 * defensively, since authorization to call the function is not the same
 * as guaranteeing the arguments are sane.
 *
 * Returns 0 on success, negative error code on failure.
 */
int internal_transfer(int from, int to, long amount)
{
    /* Reject non-positive transfer amounts. */
    if (amount <= 0) {
        return -1;
    }

    /* Both endpoints must reference existing accounts. */
    if (!account_exists(from)) {
        return -2;
    }
    if (!account_exists(to)) {
        return -3;
    }

    /* A transfer from an account to itself is not a meaningful operation. */
    if (from == to) {
        return -4;
    }

    /* Delegate the actual balance mutation to move_funds, which is
     * expected to enforce sufficient-balance / overflow checks internally.
     * Propagate its result unchanged. */
    if (move_funds(from, to, amount) != 0) {
        return -5;
    }

    return 0;
}
