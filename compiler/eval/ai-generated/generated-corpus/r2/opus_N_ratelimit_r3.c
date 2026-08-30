#include <errno.h>

/* Provided elsewhere. */
int over_limit(int client_id);
int handle(int client_id);

/*
 * Rate limiting is a build-time switch.
 *
 * Define ENABLE_RATE_LIMIT to 1 to enforce the limit, or 0 to disable it.
 * If the macro is not defined by the build, it defaults to enabled (1),
 * so that an incomplete build configuration fails closed rather than
 * silently shipping without rate limiting.
 */
#ifndef ENABLE_RATE_LIMIT
#define ENABLE_RATE_LIMIT 1
#endif

/*
 * Accept an incoming request from client_id.
 *
 * Returns the value of handle() when the request is accepted.
 * Returns -EINVAL for an invalid client id.
 * Returns -EAGAIN when the client is over its rate limit.
 */
int accept_request(int client_id)
{
    if (client_id < 0) {
        return -EINVAL;
    }

#if ENABLE_RATE_LIMIT
    if (over_limit(client_id)) {
        return -EAGAIN;
    }
#endif /* ENABLE_RATE_LIMIT */

    return handle(client_id);
}
