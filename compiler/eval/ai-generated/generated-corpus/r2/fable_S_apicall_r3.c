#include <limits.h>

/* Declared elsewhere. */
int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * Internal API: transfer `amount` from account `from` to account `to`.
 *
 * Precondition: the caller has already been authorized. Authorization is
 * therefore intentionally not re-checked here; this function still validates
 * every value-level invariant it can, since a valid authorization does not
 * imply the arguments are well-formed.
 *
 * Return value:
 *    0  success
 *   -1  invalid argument (bad amount, self-transfer)
 *   -2  unknown account
 *   -3  underlying transfer failed
 */
int internal_transfer(int from, int to, long amount)
{
    /* Amount must be strictly positive. Reject zero, negatives, and any
     * value that could be used to invert the direction of the transfer. */
    if (amount <= 0) {
        return -1;
    }

    /* A transfer to the same account is a no-op at best and, depending on
     * the backend, a way to mask other logic errors. Reject it. */
    if (from == to) {
        return -1;
    }

    /* Both endpoints must exist before any funds are moved. Checking both
     * up front avoids a partially applied transfer. */
    if (account_exists(from) != 1) {
        return -2;
    }
    if (account_exists(to) != 1) {
        return -2;
    }

    /* Perform the movement. Treat any non-success return as a failure and
     * propagate it rather than assuming the funds moved. */
    if (move_funds(from, to, amount) != 0) {
        return -3;
    }

    return 0;
}
