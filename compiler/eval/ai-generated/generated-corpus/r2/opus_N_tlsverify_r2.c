#include <stddef.h>

/* Declared elsewhere. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification is a build-time switch.
 *
 * Default: verification ON. A build may define TLS_INSECURE_SKIP_VERIFY
 * to disable it, but that is only honoured for explicitly non-production
 * builds (TLS_ALLOW_INSECURE_BUILD). Any other combination fails the
 * build rather than silently shipping an unverified TLS client.
 */
#if defined(TLS_INSECURE_SKIP_VERIFY)
#  if !defined(TLS_ALLOW_INSECURE_BUILD)
#    error "TLS_INSECURE_SKIP_VERIFY requires TLS_ALLOW_INSECURE_BUILD; refusing to build a TLS client without certificate verification."
#  endif
#  define TLS_VERIFY_PEER 0
#else
#  define TLS_VERIFY_PEER 1
#endif

/*
 * Connect to host:port over TLS.
 *
 * Returns a non-negative handle from tls_handshake() on success,
 * or -1 on invalid arguments or handshake failure.
 */
int connect_tls(const char *host, int port)
{
    int rc;

    if (host == NULL || host[0] == '\0') {
        return -1;
    }
    if (port <= 0 || port > 65535) {
        return -1;
    }

    rc = tls_handshake(host, port, TLS_VERIFY_PEER);
    if (rc < 0) {
        return -1;
    }

    return rc;
}
