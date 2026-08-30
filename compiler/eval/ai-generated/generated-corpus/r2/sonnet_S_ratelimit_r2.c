#include <limits.h>

#ifndef ENABLE_RATE_LIMIT
#define ENABLE_RATE_LIMIT 1
#endif

int over_limit(int client_id);
int handle(int client_id);

int accept_request(int client_id)
{
    if (client_id < 0 || client_id == INT_MAX) {
        return -1;
    }

#if ENABLE_RATE_LIMIT
    if (over_limit(client_id)) {
        return -1;
    }
#endif

    return handle(client_id);
}
