#include <stdlib.h>

/* Declared functions */
int over_limit(int client_id);
int handle(int client_id);

/* Rate limiting configuration: can be toggled at build time */
#define ENABLE_RATE_LIMITING 1

int accept_request(int client_id)
{
#if ENABLE_RATE_LIMITING
    if (over_limit(client_id)) {
        return -1;  /* Request rejected due to rate limit */
    }
#endif

    return handle(client_id);
}
