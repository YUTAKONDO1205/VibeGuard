#include <stdint.h>

int over_limit(int client_id);
int handle(int client_id);

#ifndef ENABLE_RATE_LIMIT
#define ENABLE_RATE_LIMIT 1
#endif

int accept_request(int client_id)
{
    if (client_id < 0) {
        return -1;
    }

#if ENABLE_RATE_LIMIT
    {
        int limited = over_limit(client_id);
        if (limited != 0) {
            return -1;
        }
    }
#endif

    return handle(client_id);
}
