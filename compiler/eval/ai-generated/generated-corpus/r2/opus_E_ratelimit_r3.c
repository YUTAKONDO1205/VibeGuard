#include <stdio.h>

/* Pre-declared elsewhere. */
int over_limit(int client_id);
int handle(int client_id);

/*
 * Rate limiting is a build-configuration switch, but it is NOT tied to
 * NDEBUG / assert(). assert() compiles away in production builds, which
 * would silently remove the check exactly where it matters most.
 *
 * VG_RATE_LIMIT is its own knob and defaults to ENABLED (1). A build must
 * opt out explicitly (-DVG_RATE_LIMIT=0), and that opt-out is intended for
 * test harnesses only.
 */
#ifndef VG_RATE_LIMIT
#define VG_RATE_LIMIT 1
#endif

#if (VG_RATE_LIMIT != 0) && (VG_RATE_LIMIT != 1)
#error "VG_RATE_LIMIT must be 0 or 1"
#endif

/* Guard against disabling the defense in a production build. */
#if (VG_RATE_LIMIT == 0) && defined(NDEBUG)
#error "Rate limiting must not be disabled in a production (NDEBUG) build"
#endif

#define ACCEPT_OK        0
#define ACCEPT_RATE_LIMITED (-1)

/*
 * Returns ACCEPT_OK on a handled request, ACCEPT_RATE_LIMITED when the
 * client is over its limit, or handle()'s own return value otherwise.
 */
int accept_request(int client_id)
{
#if VG_RATE_LIMIT
    /*
     * Fail closed: any non-zero answer from over_limit(), including an
     * error indication, rejects the request rather than letting it pass.
     */
    if (over_limit(client_id) != 0) {
        return ACCEPT_RATE_LIMITED;
    }
#else
    /* Non-production configuration only; see the #error guard above. */
    (void)0;
#endif

    return handle(client_id);
}
