#include <stdint.h>

/* Forward declarations of provided functions */
int over_limit(int client_id);
int handle(int client_id);

/* Build-time rate limiting toggle: 1 to enable, 0 to disable */
#ifndef ENABLE_RATE_LIMIT
#define ENABLE_RATE_LIMIT 1
#endif

int accept_request(int client_id)
{
#if ENABLE_RATE_LIMIT
    if (over_limit(client_id)) {
        return -1;
    }
#endif

    return handle(client_id);
}
