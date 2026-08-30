/*
 * internal_transfer - move funds between two accounts.
 *
 * Precondition: caller is already authorized (internal API).
 * Defense in depth: validate all inputs anyway; never trust the
 * precondition for anything other than authorization itself.
 *
 * Returns 0 on success, negative error code on failure.
 */

#include <limits.h>

/* Provided elsewhere. */
int account_exists(int id);
int move_funds(int from, int to, long amount);

enum {
    TRANSFER_OK             = 0,
    TRANSFER_ERR_AMOUNT     = -1,  /* non-positive or out-of-range amount */
    TRANSFER_ERR_SAME_ACCT  = -2,  /* from == to */
    TRANSFER_ERR_NO_SRC     = -3,  /* source account does not exist */
    TRANSFER_ERR_NO_DST     = -4,  /* destination account does not exist */
    TRANSFER_ERR_MOVE       = -5   /* move_funds failed */
};

int internal_transfer(int from, int to, long amount)
{
    /* Reject zero and negative amounts: a negative amount would silently
     * reverse the direction of the transfer. */
    if (amount <= 0) {
        return TRANSFER_ERR_AMOUNT;
    }

    /* Reject LONG_MAX as a defensive bound against sentinel/overflow
     * values produced by upstream parsing errors. */
    if (amount == LONG_MAX) {
        return TRANSFER_ERR_AMOUNT;
    }

    /* Self-transfer is either a no-op or a way to game fee/bonus logic;
     * refuse it explicitly. */
    if (from == to) {
        return TRANSFER_ERR_SAME_ACCT;
    }

    /* Validate both accounts before touching any funds. */
    if (!account_exists(from)) {
        return TRANSFER_ERR_NO_SRC;
    }
    if (!account_exists(to)) {
        return TRANSFER_ERR_NO_DST;
    }

    /* Delegate the actual (atomic) movement; propagate failure.
     * move_funds is responsible for balance checks and atomicity;
     * we must not report success unless it does. */
    if (move_funds(from, to, amount) != 0) {
        return TRANSFER_ERR_MOVE;
    }

    return TRANSFER_OK;
}
