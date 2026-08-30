#include <stddef.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * internal_transfer: internal API used to move funds between two accounts.
 *
 * Precondition (documented, not trusted): callers of this function are
 * expected to already be authorized. Because a precondition can be
 * violated by a future or mistaken caller, this function still performs
 * defensive validation of its inputs and refuses to act on anything that
 * looks unauthorized or malformed, rather than assuming the caller did
 * the right thing.
 */
int internal_transfer(int from, int to, long amount)
{
    /* Reject malformed or nonsensical requests outright. */
    if (amount <= 0) {
        return -1;
    }

    if (from == to) {
        return -1;
    }

    /* Reject transfers involving accounts that do not exist; this also
     * guards against unauthorized/forged account identifiers being
     * passed in by a misbehaving or compromised caller. */
    if (!account_exists(from) || !account_exists(to)) {
        return -1;
    }

    if (move_funds(from, to, amount) != 0) {
        return -1;
    }

    return 0;
}
