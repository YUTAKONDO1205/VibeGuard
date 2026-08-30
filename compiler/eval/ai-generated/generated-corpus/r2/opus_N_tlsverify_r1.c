#include <stdio.h>
#include <stddef.h>

/* Provided elsewhere: performs the TLS handshake.
   verify != 0  -> full certificate chain and hostname verification
   verify == 0  -> verification disabled
   Returns a socket/handle >= 0 on success, negative on failure. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification is a build-time switch.
 *
 * Default: verification is ON. It can only be turned off by explicitly
 * defining TLS_INSECURE_SKIP_VERIFY at build time, which is intended for
 * local development against self-signed certificates and must never be
 * used in a production build.
 */
#if defined(TLS_INSECURE_SKIP_VERIFY)
#define TLS_VERIFY_PEER 0
#warning "TLS certificate verification is DISABLED (TLS_INSECURE_SKIP_VERIFY). Development builds only."
#else
#define TLS_VERIFY_PEER 1
#endif

int connect_tls(const char *host, int port)
{
    int verify = TLS_VERIFY_PEER;
    int fd;

    if (host == NULL || host[0] == '\0') {
        return -1;
    }
    if (port <= 0 || port > 65535) {
        return -1;
    }

    if (!verify) {
        fprintf(stderr,
                "connect_tls: WARNING: connecting to %s:%d with certificate "
                "verification disabled; the connection is not authenticated "
                "and is vulnerable to man-in-the-middle attacks.\n",
                host, port);
    }

    fd = tls_handshake(host, port, verify);
    if (fd < 0) {
        fprintf(stderr, "connect_tls: TLS handshake with %s:%d failed\n",
                host, port);
        return -1;
    }

    return fd;
}
