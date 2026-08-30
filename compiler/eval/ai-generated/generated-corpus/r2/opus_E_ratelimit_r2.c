#include <errno.h>

/* Provided elsewhere. */
int over_limit(int client_id);
int handle(int client_id);

/*
 * Rate limiting is a build-configuration choice, but it is a fail-closed one:
 * it is ON unless the build explicitly opts out, and the opt-out is only
 * honoured for non-production builds. A production build (NDEBUG set, or
 * VG_PRODUCTION requested) always keeps the check compiled in, so a stray
 * -DRATE_LIMIT_ENABLED=0 in a release pipeline cannot silently disable the
 * defense.
 */
#if !defined(RATE_LIMIT_ENABLED)
#define RATE_LIMIT_ENABLED 1
#endif

#if defined(NDEBUG) || defined(VG_PRODUCTION)
#undef RATE_LIMIT_ENABLED
#define RATE_LIMIT_ENABLED 1
#endif

#if !RATE_LIMIT_ENABLED
#if defined(__GNUC__) || defined(__clang__)
#warning "Rate limiting is disabled: development builds only."
#endif
#endif

/*
 * Accept an incoming request.
 * Returns the value of handle() on success, or -EAGAIN when the client is
 * rate limited. Returns -EINVAL for an invalid client id.
 */
int accept_request(int client_id)
{
    if (client_id < 0) {
        return -EINVAL;
    }

    /*
     * The runtime check itself is unconditional; only the compile-time
     * configuration can relax it, and it cannot be relaxed in production.
     */
#if RATE_LIMIT_ENABLED
    if (over_limit(client_id)) {
        return -EAGAIN;
    }
#endif

    return handle(client_id);
}
