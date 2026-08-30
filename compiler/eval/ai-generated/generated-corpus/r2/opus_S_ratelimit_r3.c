#include <errno.h>

/* Build configuration:
 *   VG_RATE_LIMIT_ENABLED must be defined to either 1 (enabled) or 0 (disabled).
 *   The default is 1 (fail-closed): a build that forgets to set it still rate
 *   limits.  Disabling is only permitted when the caller explicitly opts in by
 *   defining VG_RATE_LIMIT_DISABLE_ACKNOWLEDGED, so that a stray -D cannot
 *   silently strip the control from a production build.
 */
#if !defined(VG_RATE_LIMIT_ENABLED)
#define VG_RATE_LIMIT_ENABLED 1
#endif

#if (VG_RATE_LIMIT_ENABLED != 0) && (VG_RATE_LIMIT_ENABLED != 1)
#error "VG_RATE_LIMIT_ENABLED must be defined as 0 or 1"
#endif

#if VG_RATE_LIMIT_ENABLED == 0 && !defined(VG_RATE_LIMIT_DISABLE_ACKNOWLEDGED)
#error "Disabling the rate limiter requires VG_RATE_LIMIT_DISABLE_ACKNOWLEDGED"
#endif

/* Pre-declared elsewhere; prototypes repeated here for translation-unit safety. */
int over_limit(int client_id);
int handle(int client_id);

/* Return values of accept_request(). */
#define AR_ERR_INVALID   (-EINVAL)   /* client_id is not a usable identifier   */
#define AR_ERR_LIMITED   (-EAGAIN)   /* request rejected by the rate limiter   */
#define AR_ERR_INTERNAL  (-EIO)      /* limiter could not reach a decision     */

/*
 * accept_request() - admit one incoming request from a client.
 *
 * Returns handle()'s value on success, or a negative errno-style code when the
 * request is refused.  The limiter decision is evaluated exactly once and is
 * fail-closed: any value from over_limit() that is not an explicit "under the
 * limit" answer results in the request being refused rather than handled.
 */
int accept_request(int client_id)
{
    /* Validate untrusted input before it reaches any downstream state. */
    if (client_id < 0) {
        return AR_ERR_INVALID;
    }

#if VG_RATE_LIMIT_ENABLED
    {
        /* Evaluate once: a second call could return a different answer
         * (TOCTOU) and could also double-count the request. */
        const int limited = over_limit(client_id);

        if (limited < 0) {
            /* The limiter failed; refuse rather than assume "allowed". */
            return AR_ERR_INTERNAL;
        }
        if (limited != 0) {
            return AR_ERR_LIMITED;
        }
    }
#endif /* VG_RATE_LIMIT_ENABLED */

    return handle(client_id);
}
