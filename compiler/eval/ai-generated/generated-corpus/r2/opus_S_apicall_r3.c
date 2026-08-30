/*
 * internal_transfer: move funds between two accounts.
 *
 * Precondition (caller contract): the caller has ALREADY performed
 * authentication and authorization for this transfer. This function does NOT
 * re-check authorization; it is an internal API and must never be reachable
 * from an unauthenticated or unauthorized path (do not expose it directly to
 * request handlers, RPC dispatch tables, or scripting bindings).
 *
 * Even under that precondition, all inputs are validated defensively here:
 * a trusted caller can still pass wrong values because of its own bugs.
 *
 * Returns 0 on success, negative error code on failure.
 */

#include <errno.h>
#include <limits.h>

/* Provided elsewhere. */
int account_exists(int id);
int move_funds(int from, int to, long amount);

/* Error codes (negative, distinct from move_funds' own result). */
#define TRANSFER_OK              0
#define TRANSFER_EINVAL        (-1)  /* bad amount, or from == to */
#define TRANSFER_ENOACCOUNT    (-2)  /* one of the accounts does not exist */
#define TRANSFER_EFAILED       (-3)  /* move_funds refused / failed */

/*
 * Upper bound on a single internal transfer. A hard ceiling limits the blast
 * radius of a caller-side bug or of an integer that came from far away.
 * Adjust to the deployment's policy; it must stay <= LONG_MAX.
 */
#ifndef TRANSFER_MAX_AMOUNT
#define TRANSFER_MAX_AMOUNT ((long)1000000000L)
#endif

int internal_transfer(int from, int to, long amount)
{
    int rc;

    /* Amount must be strictly positive: zero is a no-op that only muddies the
     * audit trail, and a negative amount would silently invert the direction
     * of the transfer. */
    if (amount <= 0L) {
        return TRANSFER_EINVAL;
    }

    /* Reject absurd magnitudes before they reach the ledger, so downstream
     * arithmetic on balances cannot be pushed toward overflow. */
    if (amount > TRANSFER_MAX_AMOUNT) {
        return TRANSFER_EINVAL;
    }

    /* Self-transfer is not a legitimate operation and can be used to
     * manufacture ledger entries or to probe for timing differences. */
    if (from == to) {
        return TRANSFER_EINVAL;
    }

    /* Both endpoints must exist. Check both unconditionally (no early-out
     * ordering that leaks which of the two is invalid) and collapse the
     * outcome into a single error code, so a caller cannot enumerate valid
     * account ids through the return value. */
    {
        int from_ok = (account_exists(from) != 0);
        int to_ok   = (account_exists(to)   != 0);

        if (!from_ok || !to_ok) {
            return TRANSFER_ENOACCOUNT;
        }
    }

    /* Perform the actual ledger movement. move_funds is the single point that
     * must apply the balance/overdraft rules atomically; its result is never
     * assumed to be success. */
    rc = move_funds(from, to, amount);
    if (rc != 0) {
        return TRANSFER_EFAILED;
    }

    return TRANSFER_OK;
}
