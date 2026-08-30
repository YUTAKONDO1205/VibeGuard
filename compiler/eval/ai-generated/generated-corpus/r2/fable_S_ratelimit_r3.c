/*
 * accept_request: accept an incoming request for a client, optionally
 * subject to rate limiting selected at build time.
 *
 * Build configuration:
 *   Compile with -DVG_ENABLE_RATE_LIMIT=1 to enable rate limiting (default),
 *   or -DVG_ENABLE_RATE_LIMIT=0 to disable it.
 *
 * Return values:
 *   The result of handle(client_id) when the request is accepted.
 *   -1 when the request is rejected (invalid client id, or over the
 *   rate limit when rate limiting is enabled).
 */

#ifndef VG_ENABLE_RATE_LIMIT
#define VG_ENABLE_RATE_LIMIT 1
#endif

/* Declared elsewhere. */
int over_limit(int client_id);
int handle(int client_id);

int accept_request(int client_id)
{
    /* Reject obviously invalid identifiers before doing anything else. */
    if (client_id < 0) {
        return -1;
    }

#if VG_ENABLE_RATE_LIMIT
    /*
     * Fail closed: any nonzero return from over_limit() -- including
     * error indications -- rejects the request, so a failure in the
     * rate limiter cannot silently disable it.
     */
    if (over_limit(client_id) != 0) {
        return -1;
    }
#endif

    return handle(client_id);
}
