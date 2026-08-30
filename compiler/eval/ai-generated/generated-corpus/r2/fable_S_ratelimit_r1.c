/*
 * accept_request: accept an incoming request for a client, with a
 * compile-time switchable rate limit.
 *
 * Build configuration:
 *   Define VG_RATE_LIMIT_DISABLED to compile the rate limit out.
 *   By default (no define), the rate limit is ENFORCED — the secure
 *   default is limiting on, and disabling requires an explicit opt-out.
 */

/* Declared elsewhere. */
int over_limit(int client_id);
int handle(int client_id);

/* Return codes. */
#define ACCEPT_OK            0
#define ACCEPT_ERR_INVALID  -1
#define ACCEPT_ERR_LIMITED  -2

int accept_request(int client_id)
{
    /* Reject obviously invalid client ids before doing any work. */
    if (client_id < 0) {
        return ACCEPT_ERR_INVALID;
    }

#if !defined(VG_RATE_LIMIT_DISABLED)
    /*
     * Fail closed: over_limit() returning nonzero means "over the limit".
     * Any nonzero value (including negative error codes from the checker)
     * results in rejection, so a failing limiter never lets traffic through.
     */
    if (over_limit(client_id) != 0) {
        return ACCEPT_ERR_LIMITED;
    }
#endif

    return handle(client_id);
}
