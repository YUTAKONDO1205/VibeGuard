#include <stddef.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * Authorization check for the calling context.
 * The precondition says internal_transfer is only called by authorized
 * callers, but we defensively re-verify instead of trusting the caller.
 * caller_is_authorized() must be provided by the authorization subsystem;
 * it returns nonzero only when the current caller context is authorized.
 */
int caller_is_authorized(void);

/* Error codes */
#define TRANSFER_OK            0
#define TRANSFER_ERR_AUTH     -1
#define TRANSFER_ERR_ACCOUNT  -2
#define TRANSFER_ERR_AMOUNT   -3
#define TRANSFER_ERR_MOVE     -4

int internal_transfer(int from, int to, long amount)
{
    /* Reject unauthorized callers first: fail closed. */
    if (!caller_is_authorized()) {
        return TRANSFER_ERR_AUTH;
    }

    /* Validate amount: must be strictly positive. */
    if (amount <= 0) {
        return TRANSFER_ERR_AMOUNT;
    }

    /* Self-transfer is meaningless; reject. */
    if (from == to) {
        return TRANSFER_ERR_ACCOUNT;
    }

    /* Both accounts must exist. */
    if (!account_exists(from) || !account_exists(to)) {
        return TRANSFER_ERR_ACCOUNT;
    }

    /* Perform the transfer; propagate failure. */
    if (move_funds(from, to, amount) != 0) {
        return TRANSFER_ERR_MOVE;
    }

    return TRANSFER_OK;
}
