#include <errno.h>
#include <limits.h>

/* Pre-declared helpers. */
int account_exists(int id);
int move_funds(int from, int to, long amount);

/*
 * Authorization for internal callers.
 *
 * The specification states that internal_transfer has a precondition: it is
 * only called by already-authorized callers.  A precondition is a claim about
 * the caller, not a guarantee enforced by this function, so it must not be
 * treated as a substitute for an authorization check.  Any caller that has
 * not established authorization in the current execution context is rejected.
 *
 * The authorization state is deliberately kept out of the argument list so a
 * caller cannot simply assert "I am authorized" by passing a flag.  It is
 * established by the authentication/authorization layer before the call and
 * cleared afterwards.
 */

/* Set only by the authorization layer; never by transfer callers. */
static int g_caller_authorized;          /* 0 = not authorized */
static int g_caller_principal = -1;      /* principal id, -1 = none */

void auth_begin_authorized_context(int principal)
{
    if (principal < 0) {
        return;                          /* refuse to open an invalid context */
    }
    g_caller_principal = principal;
    g_caller_authorized = 1;
}

void auth_end_authorized_context(void)
{
    g_caller_authorized = 0;
    g_caller_principal = -1;
}

/* Returns nonzero only when the current context is genuinely authorized. */
static int caller_is_authorized(void)
{
    return g_caller_authorized != 0 && g_caller_principal >= 0;
}

/*
 * Returns 0 on success, or a negative error code:
 *   -EACCES  caller is not authorized (fail closed)
 *   -EINVAL  arguments are not a well-formed transfer
 *   -ENOENT  one of the accounts does not exist
 *   -EIO     the underlying transfer failed
 */
int internal_transfer(int from, int to, long amount)
{
    int rc;

    /* 1. Authorization first: no work of any kind before this passes. */
    if (!caller_is_authorized()) {
        return -EACCES;
    }

    /* 2. Argument validation. */
    if (amount <= 0) {
        return -EINVAL;                  /* no zero or reversed transfers */
    }
    if (from == to) {
        return -EINVAL;
    }
    if (from < 0 || to < 0) {
        return -EINVAL;
    }

    /* 3. Existence checks. */
    if (!account_exists(from) || !account_exists(to)) {
        return -ENOENT;
    }

    /* 4. Perform the movement; never report success on a failed move. */
    rc = move_funds(from, to, amount);
    if (rc != 0) {
        return -EIO;
    }

    return 0;
}
