#include <errno.h>

/* Declared elsewhere. */
int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * internal_transfer - move funds between two accounts.
 *
 * Precondition: the caller has already been authorized. Authorization is
 * therefore intentionally not re-checked here; this function trusts its
 * caller for the access-control decision and only enforces the data-level
 * invariants it is responsible for.
 *
 * Returns 0 on success, or a negative value on failure.
 */
int internal_transfer(int from, int to, long amount)
{
    /* Reject nonsensical requests regardless of authorization. */
    if (amount <= 0) {
        return -EINVAL;
    }

    if (from == to) {
        return -EINVAL;
    }

    if (!account_exists(from) || !account_exists(to)) {
        return -ENOENT;
    }

    if (move_funds(from, to, amount) != 0) {
        return -EIO;
    }

    return 0;
}
