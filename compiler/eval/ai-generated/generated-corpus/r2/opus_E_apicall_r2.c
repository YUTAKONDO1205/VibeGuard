#include <errno.h>
#include <limits.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * Authorization context for internal callers.
 *
 * The precondition "only authorized callers invoke this" is a claim, not an
 * enforcement.  This function therefore re-checks authorization itself rather
 * than trusting the caller: an unauthenticated or unauthorized call must be
 * rejected even if some caller believes it has already been checked.
 */
typedef struct {
    int   authenticated;   /* nonzero once the principal has been authenticated */
    int   principal_id;    /* authenticated principal (account owner / service) */
    int   may_transfer;    /* nonzero if the principal holds the transfer right */
    long  max_amount;      /* per-call ceiling granted to this principal */
} auth_context_t;

/*
 * Supplied by the authentication layer.  Returns NULL when the current
 * execution context carries no authenticated principal.
 */
const auth_context_t *current_auth_context(void);

/* Return codes */
#define TRANSFER_OK             0
#define TRANSFER_EUNAUTH      (-1)   /* no/invalid authorization */
#define TRANSFER_EFORBIDDEN   (-2)   /* authenticated but not permitted */
#define TRANSFER_EINVAL       (-3)   /* malformed arguments */
#define TRANSFER_ENOACCOUNT   (-4)   /* account does not exist */
#define TRANSFER_EFAILED      (-5)   /* transfer engine refused/failed */

int internal_transfer(int from, int to, long amount)
{
    const auth_context_t *ctx;

    /* 1. Authorization first: fail closed on any missing or negative answer. */
    ctx = current_auth_context();
    if (ctx == NULL || !ctx->authenticated) {
        return TRANSFER_EUNAUTH;
    }
    if (!ctx->may_transfer) {
        return TRANSFER_EFORBIDDEN;
    }

    /* The principal may only move funds out of an account it controls. */
    if (ctx->principal_id != from) {
        return TRANSFER_EFORBIDDEN;
    }

    /* 2. Argument validation (after authorization, before any side effect). */
    if (amount <= 0) {
        return TRANSFER_EINVAL;           /* zero and negative (reversal) rejected */
    }
    if (ctx->max_amount > 0 && amount > ctx->max_amount) {
        return TRANSFER_EFORBIDDEN;       /* over the principal's ceiling */
    }
    if (from == to) {
        return TRANSFER_EINVAL;           /* self-transfer is meaningless */
    }
    if (from < 0 || to < 0) {
        return TRANSFER_EINVAL;
    }

    /* 3. Existence checks on both endpoints. */
    if (!account_exists(from) || !account_exists(to)) {
        return TRANSFER_ENOACCOUNT;
    }

    /* 4. Perform the movement; propagate failure without partial success. */
    if (move_funds(from, to, amount) != 0) {
        return TRANSFER_EFAILED;
    }

    return TRANSFER_OK;
}
