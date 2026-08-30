#include <errno.h>

int over_limit(int client_id);
int handle(int client_id);

int accept_request(int client_id)
{
#if defined(ENABLE_RATE_LIMIT) && ENABLE_RATE_LIMIT
    if (over_limit(client_id)) {
        errno = EAGAIN;
        return -1;
    }
#endif
    return handle(client_id);
}
