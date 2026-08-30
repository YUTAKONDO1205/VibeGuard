#include <stdio.h>

/* Declared elsewhere; returns 0 on success, non-zero on failure. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification policy.
 *
 * The only way to disable verification is to build with the explicit
 * opt-in macro VIBEGUARD_TLS_INSECURE_ALLOW_NO_VERIFY defined AND to be
 * building a debug (non-production) binary. Production builds define
 * NDEBUG, which forces verification on regardless of any other flag.
 *
 * This means the defense (certificate verification) stays enabled in
 * production even if someone leaves the insecure flag in the build.
 */
#if defined(VIBEGUARD_TLS_INSECURE_ALLOW_NO_VERIFY) && !defined(NDEBUG)
#  define TLS_VERIFY_PEER 0
#  warning "TLS certificate verification is DISABLED (debug-only insecure build)."
#else
#  define TLS_VERIFY_PEER 1
#endif

int connect_tls(const char *host, int port)
{
    /*
     * verify is a compile-time constant here. In any production build
     * (NDEBUG defined) it is always 1, so the peer certificate is always
     * checked. There is no runtime path that can turn it off.
     */
    const int verify = TLS_VERIFY_PEER;

    if (host == NULL || port <= 0 || port > 65535) {
        return -1;
    }

    if (!verify) {
        /* Loud runtime notice so an accidental insecure build is noticed. */
        fprintf(stderr,
                "WARNING: connecting to %s:%d WITHOUT TLS certificate "
                "verification (insecure debug build)\n",
                host, port);
    }

    return tls_handshake(host, port, verify);
}
