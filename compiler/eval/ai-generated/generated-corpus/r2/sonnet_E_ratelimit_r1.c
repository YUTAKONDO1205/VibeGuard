#include <stddef.h>

int over_limit(int client_id);
int handle(int client_id);

#ifndef VG_ENABLE_RATE_LIMIT
#define VG_ENABLE_RATE_LIMIT 1
#endif

int accept_request(int client_id)
{
#if VG_ENABLE_RATE_LIMIT
    if (over_limit(client_id)) {
        return -1;
    }
#endif
    return handle(client_id);
}
