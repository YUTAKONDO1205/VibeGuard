/*
 * accept_request: accept an incoming request for a client.
 *
 * Rate limiting is a build-time configuration switch, but it is
 * fail-closed by design:
 *
 *   - The default build ENABLES rate limiting. A build must opt out
 *     explicitly by defining VG_RATELIMIT_DISABLED, and that opt-out
 *     is deliberately noisy (see #warning below) so that shipping a
 *     limiter-less binary is a conscious act, not an accident.
 *   - Disabling the limiter never removes the call site; it only
 *     substitutes a decision function. The control flow that consults
 *     the limiter is identical in both configurations, so the enabled
 *     path cannot rot while the disabled path is being built.
 *   - over_limit() is treated as a security decision: any nonzero
 *     return, and any value that is not an unambiguous "under limit",
 *     rejects the request.
 */

#include <errno.h>
#include <limits.h>

/* Declared elsewhere. */
int over_limit(int client_id);
int handle(int client_id);

/* Return codes for accept_request(). */
#define AR_OK             0    /* request handled                       */
#define AR_INVALID      (-1)   /* malformed client id                   */
#define AR_RATE_LIMITED (-2)   /* rejected by the rate limiter          */
#define AR_UNAVAILABLE  (-3)   /* limiter could not render a decision   */

/*
 * Build configuration.
 *
 * VG_RATELIMIT_DISABLED must be defined explicitly to turn the limiter
 * off; otherwise it is on. Never invert this default: an undefined or
 * misspelled macro must fail closed (limiter on), not open.
 */
#if defined(VG_RATELIMIT_DISABLED)
#  define VG_RATELIMIT_ENABLED 0
#  warning "Rate limiting is DISABLED in this build (VG_RATELIMIT_DISABLED). Do not ship this configuration to a network-reachable deployment."
#else
#  define VG_RATELIMIT_ENABLED 1
#endif

/*
 * Validate the client id before it reaches any downstream component.
 * Negative ids and INT_MAX (commonly used as a sentinel) are rejected.
 */
static int client_id_is_valid(int client_id)
{
    return client_id >= 0 && client_id != INT_MAX;
}

/*
 * Consult the limiter.
 *
 * Returns:
 *    0  -> under the limit, request may proceed
 *    1  -> over the limit, reject
 *   -1  -> no decision available, reject (fail closed)
 *
 * over_limit() is an external predicate; we only trust the single value
 * that means "definitely under the limit". Every other value, including
 * negative error returns, is treated as "do not proceed". This keeps a
 * failing or misbehaving limiter from becoming an open door.
 */
static int rate_limit_decision(int client_id)
{
#if VG_RATELIMIT_ENABLED
    int verdict;

    errno = 0;
    verdict = over_limit(client_id);

    if (verdict == 0) {
        return 0;               /* explicitly under the limit */
    }
    if (verdict > 0) {
        return 1;               /* explicitly over the limit  */
    }
    return -1;                  /* error / unknown: fail closed */
#else
    /*
     * Limiter compiled out. The call site above is preserved; only the
     * verdict is fixed. client_id is still consumed so that this branch
     * keeps the same signature discipline and produces no unused-parameter
     * divergence between configurations.
     */
    (void)client_id;
    return 0;
#endif
}

int accept_request(int client_id)
{
    int decision;

    if (!client_id_is_valid(client_id)) {
        return AR_INVALID;
    }

    decision = rate_limit_decision(client_id);

    if (decision > 0) {
        return AR_RATE_LIMITED;
    }
    if (decision < 0) {
        return AR_UNAVAILABLE;
    }

    return handle(client_id) == 0 ? AR_OK : AR_UNAVAILABLE;
}
