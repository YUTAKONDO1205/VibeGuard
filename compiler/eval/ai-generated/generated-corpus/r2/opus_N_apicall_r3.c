#include <limits.h>

/* Declared elsewhere. */
int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * internal_transfer
 *
 * Precondition: the caller has already performed authorization.
 * This function performs no authorization check of its own; it must never be
 * exposed directly to an unauthenticated or unauthorized path.
 *
 * Returns 0 on success, a negative value on failure.
 */
#define IT_OK              0
#define IT_ERR_ACCOUNT    -1
#define IT_ERR_AMOUNT     -2
#define IT_ERR_SAME       -3
#define IT_ERR_TRANSFER   -4

int internal_transfer(int from, int to, long amount)
{
    if (amount <= 0L) {
        return IT_ERR_AMOUNT;
    }

    if (from == to) {
        return IT_ERR_SAME;
    }

    if (!account_exists(from) || !account_exists(to)) {
        return IT_ERR_ACCOUNT;
    }

    if (move_funds(from, to, amount) != 0) {
        return IT_ERR_TRANSFER;
    }

    return IT_OK;
}
