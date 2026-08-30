#include <errno.h>
#include <limits.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * Authorization model for this internal API.
 *
 * The documented precondition is that internal_transfer() is only reached
 * from an already-authorized caller.  A precondition is not an enforcement
 * mechanism: if some future call site forgets it, the money still moves.
 * So the caller must hand over proof of authorization, and this function
 * refuses every call that does not carry valid proof.
 *
 * The proof is a token established by the authorization layer for the
 * current request and installed with internal_transfer_set_auth().  It is
 * consumed (cleared) on every entry to internal_transfer(), so a token
 * authorizes exactly one transfer and cannot be replayed by a later,
 * unauthorized call site.
 */

#define TRANSFER_OK              0
#define TRANSFER_EUNAUTHORIZED (-1)
#define TRANSFER_EINVAL        (-2)
#define TRANSFER_ENOACCOUNT    (-3)
#define TRANSFER_EFAILED       (-4)

struct transfer_auth {
    int  valid;
    int  from;
    int  to;
    long amount;
};

/*
 * Request-scoped authorization state.  Single-threaded request handling is
 * assumed; with threads this must become thread-local storage.
 */
static struct transfer_auth g_auth;

/*
 * Called by the authorization layer once it has decided that this specific
 * transfer is permitted.  Binding the token to (from, to, amount) means a
 * grant for one transfer cannot be spent on a different one.
 */
void internal_transfer_set_auth(int from, int to, long amount)
{
    g_auth.valid  = 1;
    g_auth.from   = from;
    g_auth.to     = to;
    g_auth.amount = amount;
}

void internal_transfer_clear_auth(void)
{
    g_auth.valid  = 0;
    g_auth.from   = 0;
    g_auth.to     = 0;
    g_auth.amount = 0;
}

int internal_transfer(int from, int to, long amount)
{
    struct transfer_auth auth;

    /* Consume the token first: whatever happens below, it is spent. */
    auth = g_auth;
    internal_transfer_clear_auth();

    /* Refuse anything that does not carry proof for exactly this transfer. */
    if (!auth.valid ||
        auth.from != from ||
        auth.to != to ||
        auth.amount != amount) {
        return TRANSFER_EUNAUTHORIZED;
    }

    /* Argument validation, independent of authorization. */
    if (amount <= 0) {
        return TRANSFER_EINVAL;
    }
    if (from == to) {
        return TRANSFER_EINVAL;
    }

    if (!account_exists(from) || !account_exists(to)) {
        return TRANSFER_ENOACCOUNT;
    }

    if (move_funds(from, to, amount) != 0) {
        return TRANSFER_EFAILED;
    }

    return TRANSFER_OK;
}
