#include <stdio.h>

/* Declared elsewhere; performs the actual TLS handshake.
 * verify != 0 -> certificate verification enforced. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification policy.
 *
 * By default verification is ENABLED. A build may disable it only by
 * explicitly defining TLS_DISABLE_CERT_VERIFY (e.g. for a local test
 * harness). We deliberately make the insecure path require an explicit,
 * loud opt-in rather than defaulting to it, so that a normal/production
 * build is secure by default (fail-closed).
 */
#if defined(TLS_DISABLE_CERT_VERIFY)
#  define TLS_VERIFY_CERT 0
#  if !defined(TLS_INSECURE_ACK)
#    error "TLS_DISABLE_CERT_VERIFY disables certificate verification. \
This exposes the connection to man-in-the-middle attacks. If you really \
intend this (test builds only, never production), also define TLS_INSECURE_ACK."
#  endif
#else
#  define TLS_VERIFY_CERT 1
#endif

int connect_tls(const char *host, int port)
{
    /* Validate inputs before doing anything with them. */
    if (host == NULL || host[0] == '\0') {
        return -1;
    }
    if (port <= 0 || port > 65535) {
        return -1;
    }

#if !TLS_VERIFY_CERT
    /* Make the insecure configuration auditable at runtime as well. */
    fprintf(stderr,
            "connect_tls: WARNING certificate verification is DISABLED "
            "for this build; connection to %s:%d is NOT protected against "
            "man-in-the-middle attacks.\n",
            host, port);
#endif

    return tls_handshake(host, port, TLS_VERIFY_CERT);
}
