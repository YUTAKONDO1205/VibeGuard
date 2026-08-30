/*
 * internal_transfer: move funds between two accounts.
 *
 * Precondition (caller contract): the caller has ALREADY performed
 * authentication and authorization for this transfer. This function does
 * NOT re-check authorization; it only validates its own arguments and the
 * integrity of the operation it is asked to perform.
 *
 * Return value: 0 on success, negative error code on failure.
 */

#include <limits.h>
#include <errno.h>

/* Declared elsewhere. */
int account_exists(int id);
int move_funds(int from, int to, long amount);

/* Error codes (negative, distinct from move_funds' own result). */
#define TRANSFER_OK             0
#define TRANSFER_EINVAL       (-1)   /* bad argument / bad amount        */
#define TRANSFER_ENOACCT      (-2)   /* source or destination unknown    */
#define TRANSFER_ESAME        (-3)   /* self-transfer                    */
#define TRANSFER_ELIMIT       (-4)   /* amount above policy ceiling      */
#define TRANSFER_EFAILED      (-5)   /* backend refused / failed         */

/*
 * Policy ceiling for a single internal transfer. Keeps a single call from
 * moving an implausible amount even if an upstream bug produces a huge
 * value. Adjust to the deployment's actual limit.
 */
#define TRANSFER_MAX_AMOUNT   ((long)1000000000L)   /* 1e9 minor units */

int internal_transfer(int from, int to, long amount)
{
    int rc;

    /*
     * 1. Argument validation. Even a trusted caller can hold a bug, and
     *    validating here is cheap. Negative ids are rejected outright so a
     *    sentinel such as -1 can never be treated as a real account.
     */
    if (from < 0 || to < 0) {
        return TRANSFER_EINVAL;
    }

    /*
     * 2. Amount validation. Reject zero and negative amounts: a negative
     *    amount would invert the direction of the transfer and defeat every
     *    authorization decision the caller already made. Reject the
     *    implausibly large as well.
     */
    if (amount <= 0) {
        return TRANSFER_EINVAL;
    }
    if (amount > TRANSFER_MAX_AMOUNT) {
        return TRANSFER_ELIMIT;
    }

    /*
     * 3. Reject self-transfer. It is a no-op at best and, in ledgers that
     *    debit and credit in separate steps, a way to fabricate balance.
     */
    if (from == to) {
        return TRANSFER_ESAME;
    }

    /*
     * 4. Existence checks. Do these before touching funds so a typo cannot
     *    debit a real account and credit nothing.
     */
    if (account_exists(from) != 1) {
        return TRANSFER_ENOACCT;
    }
    if (account_exists(to) != 1) {
        return TRANSFER_ENOACCT;
    }

    /*
     * 5. Perform the move. The backend is the single point that must apply
     *    the debit and credit atomically; we only report its outcome.
     *    Treat anything other than success as failure - never assume the
     *    money moved.
     */
    rc = move_funds(from, to, amount);
    if (rc != 0) {
        return TRANSFER_EFAILED;
    }

    return TRANSFER_OK;
}
