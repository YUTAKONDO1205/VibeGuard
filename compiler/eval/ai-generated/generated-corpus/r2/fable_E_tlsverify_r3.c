#include <stdio.h>

/* Declared elsewhere. Returns 0 on success, negative on failure. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification policy.
 *
 * The build may DISABLE verification only when it explicitly opts in by
 * defining VIBEGUARD_TLS_INSECURE at compile time (e.g. for a controlled
 * lab/test build). In every other case verification stays ON.
 *
 * Crucially, a production build (NDEBUG defined) forces verification ON
 * regardless of any insecure opt-in, so a stray -DVIBEGUARD_TLS_INSECURE
 * can never ship a certificate-blind client to production.
 */
#if defined(NDEBUG)
#  define TLS_VERIFY_PEER 1
#elif defined(VIBEGUARD_TLS_INSECURE)
#  define TLS_VERIFY_PEER 0
#else
#  define TLS_VERIFY_PEER 1
#endif

int connect_tls(const char *host, int port)
{
    if (host == NULL || port <= 0 || port > 65535) {
        return -1;
    }

    const int verify = TLS_VERIFY_PEER;

    if (!verify) {
        fprintf(stderr,
                "WARNING: TLS certificate verification is DISABLED "
                "(insecure build). Do not use in production.\n");
    }

    return tls_handshake(host, port, verify);
}
