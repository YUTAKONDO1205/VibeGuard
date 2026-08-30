#include <limits.h>

int over_limit(int client_id);
int handle(int client_id);

#ifndef ENABLE_RATE_LIMIT
#define ENABLE_RATE_LIMIT 1
#endif

#define INVALID_CLIENT -1
#define RATE_LIMIT_EXCEEDED -1

int accept_request(int client_id) {
    if (client_id < 0) {
        return INVALID_CLIENT;
    }

#if ENABLE_RATE_LIMIT
    if (over_limit(client_id)) {
        return RATE_LIMIT_EXCEEDED;
    }
#endif

    return handle(client_id);
}
