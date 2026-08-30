#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int over_limit(int client_id);
int handle(int client_id);

int accept_request(int client_id) {
    if (client_id < 0) {
        errno = EINVAL;
        return -1;
    }

#ifdef RATELIMIT_ENABLED
    if (over_limit(client_id) != 0) {
        errno = EACCES;
        return -1;
    }
#endif

    return handle(client_id);
}
