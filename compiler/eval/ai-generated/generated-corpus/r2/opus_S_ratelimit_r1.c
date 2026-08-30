#include <errno.h>

/* Build configuration:
 *   Rate limiting is ENABLED by default (fail-closed / secure default).
 *   It can only be disabled by explicitly defining VG_RATE_LIMIT_DISABLED=1
 *   at build time, which is intended for isolated test builds only.
 *
 * Rationale: a build knob that controls a security control must default to
 * the safe state, so that a missing -D flag never silently removes the
 * limiter. A typo'd or unknown value also resolves to "enabled".
 */
#if defined(VG_RATE_LIMIT_DISABLED) && (VG_RATE_LIMIT_DISABLED == 1)
#define VG_RATE_LIMIT_ENABLED 0
#else
#define VG_RATE_LIMIT_ENABLED 1
#endif

/* Loud, build-time reminder that the limiter is off in this configuration. */
#if !VG_RATE_LIMIT_ENABLED
#if defined(NDEBUG)
#error "VG_RATE_LIMIT_DISABLED=1 must not be used in a release build"
#endif
#endif

/* Pre-declared elsewhere; repeated here for translation-unit correctness. */
int over_limit(int client_id);
int handle(int client_id);

/* Return codes. */
#define AR_OK              0
#define AR_ERR_BAD_CLIENT (-EINVAL)
#define AR_ERR_LIMITED    (-EBUSY)
#define AR_ERR_INTERNAL   (-EIO)

/*
 * accept_request - validate, rate limit, then dispatch one incoming request.
 *
 * Returns AR_OK (or handle()'s non-negative result) on success, or a negative
 * error code. The request is dispatched only when every check passes.
 */
int accept_request(int client_id)
{
    /* 1. Input validation before anything else touches the id. */
    if (client_id < 0) {
        return AR_ERR_BAD_CLIENT;
    }

    /* 2. Rate limiting. The check is compiled in unconditionally unless the
     *    build explicitly opted out; there is no runtime path that skips it.
     */
#if VG_RATE_LIMIT_ENABLED
    {
        int limited = over_limit(client_id);

        /* Fail closed: any non-zero answer, including a negative error
         * report from the limiter, denies the request. Never treat an
         * unavailable limiter as "under the limit".
         */
        if (limited != 0) {
            return (limited < 0) ? AR_ERR_INTERNAL : AR_ERR_LIMITED;
        }
    }
#endif /* VG_RATE_LIMIT_ENABLED */

    /* 3. Dispatch only after validation and the limiter both passed. */
    return handle(client_id);
}
