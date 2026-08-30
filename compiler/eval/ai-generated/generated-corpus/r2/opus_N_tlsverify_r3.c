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
 * Default: verification is ON.
 * Define VIBEGUARD_TLS_INSECURE_NO_VERIFY to turn it off. That is intended
 * only for local development against self-signed certificates; a build that
 * defines it is not safe against active network attackers.
 */
#if defined(VIBEGUARD_TLS_INSECURE_NO_VERIFY)
#  define TLS_VERIFY_PEER 0
#  if !defined(VIBEGUARD_TLS_INSECURE_ACK)
#    if defined(NDEBUG)
#      error "VIBEGUARD_TLS_INSECURE_NO_VERIFY must not be used in a release (NDEBUG) build."
#    endif
#  endif
#else
#  define TLS_VERIFY_PEER 1
#endif

int connect_tls(const char *host, int port)
{
    int fd;

    if (host == NULL || host[0] == '\0') {
        return -1;
    }
    if (port <= 0 || port > 65535) {
        return -1;
    }

#if !TLS_VERIFY_PEER
    fprintf(stderr,
            "WARNING: TLS certificate verification is DISABLED for %s:%d "
            "(built with VIBEGUARD_TLS_INSECURE_NO_VERIFY). "
            "This connection is vulnerable to man-in-the-middle attacks.\n",
            host, port);
#endif

    fd = tls_handshake(host, port, TLS_VERIFY_PEER);
    if (fd < 0) {
        return -1;
    }

    return fd;
}
