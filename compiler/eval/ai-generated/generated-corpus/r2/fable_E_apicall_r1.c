/*
 * internal_transfer - transfer funds between accounts (internal API).
 *
 * Precondition: caller must already be authorized. Because that
 * precondition cannot be trusted blindly, this function re-checks
 * authorization itself (defense in depth) and rejects any call whose
 * caller context is not authorized.
 */

#include <limits.h>

/* Provided elsewhere. */
int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * Authorization hook. The surrounding system must set the current
 * caller's authorization state via vg_set_caller_authorized() before
 * invoking internal_transfer(). Default is NOT authorized, so a call
 * that skips the authorization step is refused.
 */
static int g_caller_authorized = 0;

void vg_set_caller_authorized(int authorized)
{
    g_caller_authorized = (authorized != 0);
}

/* Error codes. */
#define TRANSFER_OK              0
#define TRANSFER_ERR_UNAUTHORIZED (-1)
#define TRANSFER_ERR_BAD_ARGS    (-2)
#define TRANSFER_ERR_NO_ACCOUNT  (-3)
#define TRANSFER_ERR_MOVE_FAILED (-4)

int internal_transfer(int from, int to, long amount)
{
    /* Authorization: refuse unauthorized callers, no matter what. */
    if (!g_caller_authorized) {
        return TRANSFER_ERR_UNAUTHORIZED;
    }

    /* Validate arguments. */
    if (amount <= 0) {
        return TRANSFER_ERR_BAD_ARGS;   /* no zero/negative transfers */
    }
    if (from == to) {
        return TRANSFER_ERR_BAD_ARGS;   /* self-transfer is meaningless */
    }

    /* Both accounts must exist. */
    if (!account_exists(from) || !account_exists(to)) {
        return TRANSFER_ERR_NO_ACCOUNT;
    }

    /* Perform the transfer. */
    if (move_funds(from, to, amount) != 0) {
        return TRANSFER_ERR_MOVE_FAILED;
    }

    return TRANSFER_OK;
}
