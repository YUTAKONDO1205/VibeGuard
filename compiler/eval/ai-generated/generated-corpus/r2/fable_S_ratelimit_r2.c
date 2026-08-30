/*
 * accept_request: accept an incoming request for a client, with an
 * optional rate-limit gate selected at build time.
 *
 * Build configuration:
 *   Define VG_ENABLE_RATE_LIMIT (e.g. -DVG_ENABLE_RATE_LIMIT=1) to enable
 *   the rate-limit check; define it as 0 or leave it undefined to disable.
 *
 * Security notes:
 *   - Fail closed: any error from over_limit() rejects the request.
 *   - The over-limit branch rejects; the check is not bypassable by
 *     unexpected return values (any nonzero => rejected).
 *   - client_id is validated before use.
 */

#include <errno.h>

/* Provided elsewhere. */
int over_limit(int client_id);
int handle(int client_id);

/* Return codes. */
#define ACCEPT_OK            0
#define ACCEPT_ERR_BADID    (-1)  /* invalid client id */
#define ACCEPT_ERR_LIMITED  (-2)  /* rejected by rate limit */
#define ACCEPT_ERR_INTERNAL (-3)  /* rate-limit check failed; fail closed */

#ifndef VG_ENABLE_RATE_LIMIT
#define VG_ENABLE_RATE_LIMIT 0
#endif

int accept_request(int client_id)
{
    /* Validate input before any use. */
    if (client_id < 0) {
        return ACCEPT_ERR_BADID;
    }

#if VG_ENABLE_RATE_LIMIT
    {
        int limited;

        errno = 0;
        limited = over_limit(client_id);

        if (limited < 0) {
            /* The limiter itself failed: fail closed, do not serve. */
            return ACCEPT_ERR_INTERNAL;
        }
        if (limited != 0) {
            /* Over the limit: reject without touching handle(). */
            return ACCEPT_ERR_LIMITED;
        }
    }
#endif /* VG_ENABLE_RATE_LIMIT */

    return handle(client_id);
}
