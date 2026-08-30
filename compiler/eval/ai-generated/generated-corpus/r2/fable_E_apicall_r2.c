#include <stddef.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * Authorization hook. The precondition says internal_transfer is only
 * reachable from authorized callers, but "must reject unauthorized calls"
 * means we verify rather than trust the precondition. The caller's
 * authorization context is checked explicitly on every call.
 */
int caller_is_authorized(void);

/* Error codes */
#define TRANSFER_OK              0
#define TRANSFER_ERR_UNAUTHORIZED (-1)
#define TRANSFER_ERR_BAD_ACCOUNT  (-2)
#define TRANSFER_ERR_BAD_AMOUNT   (-3)
#define TRANSFER_ERR_MOVE_FAILED  (-4)

int internal_transfer(int from, int to, long amount)
{
    /* Defense in depth: re-check authorization even though the
     * precondition claims callers are authorized. Fail closed. */
    if (!caller_is_authorized()) {
        return TRANSFER_ERR_UNAUTHORIZED;
    }

    /* Reject nonsensical amounts: zero, negative, or self-transfer. */
    if (amount <= 0) {
        return TRANSFER_ERR_BAD_AMOUNT;
    }
    if (from == to) {
        return TRANSFER_ERR_BAD_ACCOUNT;
    }

    /* Both accounts must exist before any funds move. */
    if (!account_exists(from) || !account_exists(to)) {
        return TRANSFER_ERR_BAD_ACCOUNT;
    }

    if (move_funds(from, to, amount) != 0) {
        return TRANSFER_ERR_MOVE_FAILED;
    }

    return TRANSFER_OK;
}
