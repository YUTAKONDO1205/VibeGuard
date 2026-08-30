#include <stddef.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * Internal API for transferring funds between accounts.
 *
 * Precondition: the caller is already authorized. Authorization is the
 * responsibility of the caller and is intentionally NOT re-checked here;
 * this function is not exposed at any trust boundary.
 *
 * Returns 0 on success, negative on failure.
 */
int internal_transfer(int from, int to, long amount)
{
    /* Reject nonsensical requests early. */
    if (amount <= 0)
        return -1;

    /* A self-transfer is a no-op that should not reach move_funds. */
    if (from == to)
        return -2;

    /* Both accounts must exist before any funds are moved. */
    if (!account_exists(from) || !account_exists(to))
        return -3;

    /* Delegate the actual balance mutation. */
    if (move_funds(from, to, amount) != 0)
        return -4;

    return 0;
}
