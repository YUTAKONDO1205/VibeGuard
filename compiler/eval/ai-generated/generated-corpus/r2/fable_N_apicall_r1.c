#include <errno.h>

/* Declared elsewhere. */
int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * internal_transfer
 *
 * Internal API to move funds between two accounts.
 *
 * Precondition: the caller has already been authorized. This function is only
 * ever invoked from authorized call sites, so it performs no authorization
 * check of its own; it validates only the transfer arguments.
 *
 * Returns 0 on success, or a negative value on error.
 */
int internal_transfer(int from, int to, long amount)
{
    /* A transfer to and from the same account is a no-op / meaningless. */
    if (from == to) {
        return -EINVAL;
    }

    /* Amount must be strictly positive. */
    if (amount <= 0) {
        return -EINVAL;
    }

    /* Both endpoints must refer to existing accounts. */
    if (!account_exists(from) || !account_exists(to)) {
        return -ENOENT;
    }

    /* Perform the actual movement of funds. */
    if (move_funds(from, to, amount) != 0) {
        return -EIO;
    }

    return 0;
}
