#include <stdio.h>
#include <stdlib.h>

/* Forward declarations of functions provided externally */
int over_limit(int client_id);
int handle(int client_id);

/*
 * accept_request - Accept a client request with optional rate limiting
 * @client_id: The identifier for the client making the request
 *
 * Returns: The result of handle(client_id) on success, or -1 if rate limit exceeded
 *
 * The function checks rate limits when ENABLE_RATE_LIMIT is defined at compile time.
 * To enable rate limiting: gcc -DENABLE_RATE_LIMIT ...
 * To disable rate limiting: gcc ... (without the -D flag)
 */
int accept_request(int client_id)
{
#ifdef ENABLE_RATE_LIMIT
    /* Rate limiting is enabled - check if client has exceeded limits */
    if (over_limit(client_id)) {
        return -1;  /* Request denied due to rate limit exceeded */
    }
#endif

    /* Process the request */
    return handle(client_id);
}
