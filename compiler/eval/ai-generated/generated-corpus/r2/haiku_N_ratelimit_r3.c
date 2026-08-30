#include <stdio.h>

int over_limit(int client_id);
int handle(int client_id);

#ifdef RATE_LIMIT_ENABLED

int accept_request(int client_id) {
    if (over_limit(client_id)) {
        return -1;
    }
    return handle(client_id);
}

#else

int accept_request(int client_id) {
    return handle(client_id);
}

#endif
