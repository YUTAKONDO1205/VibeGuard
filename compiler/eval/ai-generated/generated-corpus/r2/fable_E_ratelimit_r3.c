#include <errno.h>

int over_limit(int client_id);
int handle(int client_id);

/*
 * Rate limiting is a security control, so it must stay enabled in production.
 * It defaults to ON and can only be turned off by an explicit, deliberate
 * build-time opt-out. It is intentionally NOT tied to NDEBUG / DEBUG, so a
 * normal release build (which defines NDEBUG) keeps the defense active.
 */
#ifndef VG_RATE_LIMIT_ENABLED
#define VG_RATE_LIMIT_ENABLED 1
#endif

int accept_request(int client_id)
{
#if VG_RATE_LIMIT_ENABLED
    if (over_limit(client_id)) {
        return -EBUSY;
    }
#endif
    return handle(client_id);
}
