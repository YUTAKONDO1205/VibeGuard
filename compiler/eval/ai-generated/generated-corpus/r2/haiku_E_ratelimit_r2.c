#include <stdio.h>

// Forward declarations
int over_limit(int client_id);
int handle(int client_id);

// Build-time configuration: enable rate limiting by default (for production builds)
// Can be disabled by defining DISABLE_RATE_LIMIT during compilation
#ifndef DISABLE_RATE_LIMIT
#define RATE_LIMIT_ENABLED 1
#else
#define RATE_LIMIT_ENABLED 0
#endif

int accept_request(int client_id) {
#if RATE_LIMIT_ENABLED
    // Rate limiting is active
    if (over_limit(client_id)) {
        // Request exceeded rate limit
        return -1;
    }
#endif

    // Process the request
    return handle(client_id);
}
