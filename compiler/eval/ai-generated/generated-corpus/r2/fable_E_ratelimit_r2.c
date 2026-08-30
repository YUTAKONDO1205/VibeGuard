/*
 * accept_request: accept an incoming request, subject to rate limiting.
 *
 * Build configuration:
 *   The rate limit is ON by default in every build, including release
 *   builds (it is deliberately NOT tied to NDEBUG or assert(), so that
 *   production builds keep the defense enabled).
 *
 *   To disable it, a build must opt out explicitly:
 *       -DVG_DISABLE_RATE_LIMIT=1
 */

int over_limit(int client_id);
int handle(int client_id);

#ifndef VG_DISABLE_RATE_LIMIT
#define VG_DISABLE_RATE_LIMIT 0
#endif

/* Returned when a request is rejected by the rate limiter. */
#ifndef VG_ERR_RATE_LIMITED
#define VG_ERR_RATE_LIMITED (-1)
#endif

int accept_request(int client_id)
{
#if !VG_DISABLE_RATE_LIMIT
    /*
     * Fail closed: any nonzero answer from over_limit() — including
     * negative error codes — is treated as "do not accept".
     */
    if (over_limit(client_id) != 0) {
        return VG_ERR_RATE_LIMITED;
    }
#endif
    return handle(client_id);
}
