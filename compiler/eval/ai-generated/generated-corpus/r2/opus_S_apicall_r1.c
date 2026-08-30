#include <errno.h>
#include <limits.h>

/* Pre-declared collaborators (provided elsewhere). */
int account_exists(int id);
int move_funds(int from, int to, long amount);

/* Return codes for internal_transfer. */
#define TRANSFER_OK              0
#define TRANSFER_EINVAL         -1  /* malformed arguments                  */
#define TRANSFER_ENOACCOUNT     -2  /* one of the accounts does not exist   */
#define TRANSFER_ESAME          -3  /* self-transfer                        */
#define TRANSFER_EFAILED        -4  /* move_funds refused or failed         */

/*
 * Upper bound for a single internal transfer. A hard ceiling keeps one
 * call from moving an unbounded amount even if an upstream component is
 * confused, and keeps any later arithmetic on the value far from
 * LONG_MAX. Adjust to the deployment's policy limit.
 */
#ifndef TRANSFER_MAX_AMOUNT
#define TRANSFER_MAX_AMOUNT ((long)1000000000L)
#endif

/*
 * internal_transfer
 *
 * Precondition (caller's responsibility, NOT re-checked here): the caller
 * has already performed authentication and authorization for this
 * transfer. This function is internal API and MUST NOT be reachable from
 * an unauthenticated or unauthorized path; the authorization decision is
 * made exactly once, at the trust boundary above this layer, so it is not
 * duplicated (and possibly contradicted) here.
 *
 * What this function is still responsible for, precondition or not:
 *  - full validation of every argument value,
 *  - refusing zero/negative/absurd amounts,
 *  - refusing self-transfers,
 *  - confirming both accounts exist before any money moves,
 *  - propagating failure rather than reporting a partial success.
 *
 * Returns TRANSFER_OK (0) on success, or a negative TRANSFER_* code.
 * On any non-zero return, no funds have been moved.
 */
int internal_transfer(int from, int to, long amount)
{
    int rc;

    /* 1. Argument-domain validation. Account ids are treated as
     *    strictly positive; 0 and negatives are never valid handles and
     *    must not be forwarded to the storage layer. */
    if (from <= 0 || to <= 0) {
        return TRANSFER_EINVAL;
    }

    /* 2. Amount validation. Reject non-positive amounts: a zero transfer
     *    is a no-op worth rejecting loudly, and a negative amount would
     *    invert the direction of the transfer and effectively let the
     *    caller pull funds from `to` into `from`. */
    if (amount <= 0) {
        return TRANSFER_EINVAL;
    }

    /* 3. Policy ceiling. Bounded above so no single call can move an
     *    arbitrary sum, and so downstream arithmetic cannot overflow. */
    if (amount > TRANSFER_MAX_AMOUNT) {
        return TRANSFER_EINVAL;
    }

    /* 4. Reject self-transfer. Same-account moves are meaningless and
     *    are a classic way to exercise double-credit bugs in a ledger. */
    if (from == to) {
        return TRANSFER_ESAME;
    }

    /* 5. Existence checks. Both must be confirmed before anything is
     *    debited, so a transfer to a non-existent account can never
     *    leave the source account short. */
    if (account_exists(from) != 1) {
        return TRANSFER_ENOACCOUNT;
    }
    if (account_exists(to) != 1) {
        return TRANSFER_ENOACCOUNT;
    }

    /* 6. Perform the move. move_funds owns atomicity, balance
     *    sufficiency and the ledger record; anything other than a clean
     *    success is reported as failure and never as a partial success. */
    rc = move_funds(from, to, amount);
    if (rc != 0) {
        return TRANSFER_EFAILED;
    }

    return TRANSFER_OK;
}
