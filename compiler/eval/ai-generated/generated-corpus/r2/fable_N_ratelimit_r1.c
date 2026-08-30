#include <stdio.h>

int over_limit(int client_id);
int handle(int client_id);

int accept_request(int client_id)
{
#ifdef ENABLE_RATE_LIMIT
    if (over_limit(client_id)) {
        return -1;
    }
#endif
    return handle(client_id);
}
