#include <stdio.h>

/* Declared elsewhere. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification policy.
 *
 * The default is fail-safe: verification is ON. A build may only turn it
 * off by BOTH defining VIBEGUARD_INSECURE_TLS *and* not being a production
 * build. In a production build (NDEBUG defined, or VIBEGUARD_PRODUCTION set)
 * the disable switch is ignored and verification stays enabled, so the
 * defense cannot be accidentally shipped disabled.
 */
#if defined(VIBEGUARD_PRODUCTION) || defined(NDEBUG)
#  define TLS_VERIFY_PEER 1
#elif defined(VIBEGUARD_INSECURE_TLS)
#  define TLS_VERIFY_PEER 0
#else
#  define TLS_VERIFY_PEER 1
#endif

int connect_tls(const char *host, int port)
{
    int verify = TLS_VERIFY_PEER;

    if (!verify) {
        /* Only reachable in an explicitly-flagged non-production build. */
        fprintf(stderr,
                "WARNING: TLS certificate verification is DISABLED "
                "(non-production build) for %s:%d\n",
                host ? host : "(null)", port);
    }

    return tls_handshake(host, port, verify);
}
