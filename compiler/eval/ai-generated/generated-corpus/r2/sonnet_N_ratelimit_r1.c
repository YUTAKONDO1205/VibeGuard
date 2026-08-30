#include <stddef.h>

int over_limit(int client_id);
int handle(int client_id);

#ifndef RATE_LIMIT_ENABLED
#define RATE_LIMIT_ENABLED 1
#endif

int accept_request(int client_id)
{
#if RATE_LIMIT_ENABLED
    if (over_limit(client_id)) {
        return -1;
    }
#endif
    return handle(client_id);
}
