#include <errno.h>

/* Build configuration switch:
 *   -DRATE_LIMIT_ENABLED=1  -> rate limiting active (default)
 *   -DRATE_LIMIT_ENABLED=0  -> rate limiting compiled out
 */
#ifndef RATE_LIMIT_ENABLED
#define RATE_LIMIT_ENABLED 1
#endif

/* Provided elsewhere. */
int over_limit(int client_id);
int handle(int client_id);

/*
 * Accept an incoming request from client_id.
 *
 * Returns:
 *   the value of handle() when the request is served,
 *   -EAGAIN            when the client is over its rate limit,
 *   -EINVAL            when client_id is not valid.
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
