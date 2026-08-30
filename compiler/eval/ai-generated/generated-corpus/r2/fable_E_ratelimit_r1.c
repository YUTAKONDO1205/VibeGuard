/*
 * accept_request: accept an incoming request for a client.
 *
 * Rate limiting is build-configurable via VG_DISABLE_RATE_LIMIT:
 *   - By default (including production/NDEBUG builds), rate limiting is ON.
 *   - Define VG_DISABLE_RATE_LIMIT explicitly to compile it out.
 *
 * The check deliberately does NOT use assert() or any NDEBUG-dependent
 * mechanism, so release builds keep the defense active.
 */

int over_limit(int client_id);
int handle(int client_id);

#define VG_ACCEPT_REJECTED (-1)

int accept_request(int client_id)
{
#ifndef VG_DISABLE_RATE_LIMIT
    if (over_limit(client_id)) {
        return VG_ACCEPT_REJECTED;
    }
#endif
    return handle(client_id);
}
