#include <errno.h>

/* Build configuration switch.
 *
 * Rate limiting is ON by default. A build may disable it explicitly by
 * defining RATE_LIMIT_ENABLED to 0 (e.g. -DRATE_LIMIT_ENABLED=0).
 */
#ifndef RATE_LIMIT_ENABLED
#define RATE_LIMIT_ENABLED 1
#endif

/* Declared elsewhere. */
int over_limit(int client_id);
int handle(int client_id);

/* Accept an incoming request from client_id.
 *
 * Returns whatever handle() returns on success.
 * Returns -EINVAL for an invalid client id.
 * Returns -EAGAIN when the client is over its rate limit.
 */
int accept_request(int client_id)
{
    if (client_id < 0) {
        return -EINVAL;
    }

#if RATE_LIMIT_ENABLED
    if (over_limit(client_id)) {
        return -EAGAIN;
    }
#endif

    return handle(client_id);
}
