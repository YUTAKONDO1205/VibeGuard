/*
 * connect_tls: establish a TLS connection.
 *
 * Certificate verification is a build-configurable knob, but it is
 * fail-closed: verification is ON unless the build explicitly opts out,
 * and the opt-out is refused in production builds.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Provided elsewhere. Returns >= 0 (a socket/handle) on success, < 0 on error. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Build configuration.
 *
 * VG_TLS_INSECURE_SKIP_VERIFY may be defined by a developer to disable
 * certificate verification for local testing against self-signed certs.
 * It is only honoured in non-production builds: if NDEBUG is defined
 * (the usual marker of a release/production build) and the opt-out was
 * requested, the build fails loudly rather than silently shipping a
 * client that trusts any certificate.
 */
#if defined(VG_TLS_INSECURE_SKIP_VERIFY)
#  if defined(NDEBUG) || defined(VG_PRODUCTION)
#    error "VG_TLS_INSECURE_SKIP_VERIFY must not be enabled in a production build"
#  endif
#  define VG_TLS_VERIFY_DEFAULT 0
#else
#  define VG_TLS_VERIFY_DEFAULT 1
#endif

#define VG_TLS_PORT_MIN 1
#define VG_TLS_PORT_MAX 65535

int connect_tls(const char *host, int port)
{
    int verify = VG_TLS_VERIFY_DEFAULT;
    int fd;

    if (host == NULL || host[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (port < VG_TLS_PORT_MIN || port > VG_TLS_PORT_MAX) {
        errno = EINVAL;
        return -1;
    }

    if (!verify) {
        /* Unreachable in production builds: guarded by the #error above. */
        fprintf(stderr,
                "WARNING: TLS certificate verification is DISABLED for %s:%d "
                "(development build only).\n",
                host, port);
    }

    fd = tls_handshake(host, port, verify);
    if (fd < 0) {
        fprintf(stderr, "TLS handshake with %s:%d failed.\n", host, port);
        return -1;
    }

    return fd;
}
