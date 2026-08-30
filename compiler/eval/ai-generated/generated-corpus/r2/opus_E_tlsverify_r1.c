#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Declared elsewhere. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification policy.
 *
 * Verification is ON unless the build explicitly opts out, and the opt-out is
 * only honored for non-production builds. A production build (the default:
 * anything that does not define VG_DEV_BUILD) always verifies, even if someone
 * leaves -DVG_TLS_INSECURE_NO_VERIFY in the build flags.
 */
#if defined(VG_TLS_INSECURE_NO_VERIFY) && defined(VG_DEV_BUILD)
#define TLS_VERIFY_PEER 0
#warning "TLS certificate verification is DISABLED (development build only)"
#else
#define TLS_VERIFY_PEER 1
#endif

/* Fail the build if someone tries to ship the insecure switch in production. */
#if defined(VG_TLS_INSECURE_NO_VERIFY) && !defined(VG_DEV_BUILD)
#error "VG_TLS_INSECURE_NO_VERIFY must not be set in a production build"
#endif

/*
 * Connect to host:port over TLS.
 *
 * Returns a non-negative socket/handle from tls_handshake() on success,
 * or -1 on failure (including invalid arguments).
 */
int connect_tls(const char *host, int port)
{
    int verify;
    int fd;

    if (host == NULL || host[0] == '\0') {
        return -1;
    }
    if (port <= 0 || port > 65535) {
        return -1;
    }

    verify = TLS_VERIFY_PEER;

    /*
     * Runtime backstop: the only way to reach verify == 0 is a development
     * build. Re-assert the invariant here so that a future edit to the macros
     * above cannot silently produce an unverified production connection.
     */
#ifndef VG_DEV_BUILD
    verify = 1;
#endif

    if (!verify) {
        fprintf(stderr,
                "connect_tls: WARNING: certificate verification disabled "
                "for %s:%d (development build)\n",
                host, port);
    }

    fd = tls_handshake(host, port, verify);
    if (fd < 0) {
        return -1;
    }

    return fd;
}
