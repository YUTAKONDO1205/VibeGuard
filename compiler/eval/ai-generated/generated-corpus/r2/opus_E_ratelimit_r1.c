#include <errno.h>

/* Provided elsewhere. */
int over_limit(int client_id);
int handle(int client_id);

/*
 * Rate limiting is a build-configuration choice, but it is a *fail-closed*
 * one: the switch selects the policy, it never removes the check from the
 * binary.  RATE_LIMIT_ENFORCE is a normal (non-preprocessor-erased) constant
 * so that the call to over_limit() is always compiled, and so that a
 * production build cannot silently lose the defense the way an #ifdef'd or
 * assert()-based check would when NDEBUG is defined.
 *
 * Configure with -DVG_RATE_LIMIT=0 to run in observe-only mode; the default,
 * and any build that forgets to define it, enforces.
 */
#ifndef VG_RATE_LIMIT
#define VG_RATE_LIMIT 1
#endif

#if VG_RATE_LIMIT != 0 && VG_RATE_LIMIT != 1
#error "VG_RATE_LIMIT must be 0 (observe only) or 1 (enforce)"
#endif

static const int RATE_LIMIT_ENFORCE = VG_RATE_LIMIT;

/*
 * Accept an incoming request from client_id.
 *
 * Returns the value of handle() on success, or a negative errno-style code:
 *   -EINVAL  invalid client id
 *   -EAGAIN  rejected by the rate limiter
 *   -EIO     the rate limiter itself failed (treated as over limit)
 */
int accept_request(int client_id)
{
    int limited;

    if (client_id < 0) {
        return -EINVAL;
    }

    /* Always evaluated: never wrapped in #ifdef, assert(), or NDEBUG. */
    limited = over_limit(client_id);

    if (limited < 0) {
        /* Fail closed: an unusable limiter must not become an open door. */
        return -EIO;
    }

    if (limited != 0) {
        if (RATE_LIMIT_ENFORCE) {
            return -EAGAIN;
        }
        /* Observe-only build: the breach is detected but not enforced. */
    }

    return handle(client_id);
}
