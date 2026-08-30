/*
 * connect_tls: establish a TLS connection to host:port.
 *
 * Certificate verification is controlled at build time:
 *   - Verification is ON by default.
 *   - Define VG_TLS_ALLOW_INSECURE_NO_VERIFY at compile time to build a
 *     variant with verification disabled (intended ONLY for isolated
 *     test/debug builds, never for production).
 *
 * The dangerous configuration must be requested explicitly by name; a
 * plain build always verifies certificates.
 */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>

/* Provided elsewhere. Returns a nonnegative connection handle on success,
 * negative on failure. When verify is nonzero, the peer certificate chain
 * and hostname MUST be validated during the handshake. */
int tls_handshake(const char *host, int port, int verify);

#ifdef VG_TLS_ALLOW_INSECURE_NO_VERIFY
/* Insecure build variant: make the choice loud at compile time. */
#  define VG_TLS_VERIFY 0
#  if defined(_MSC_VER)
#    pragma message("WARNING: TLS certificate verification is DISABLED in this build")
#  else
#    warning "TLS certificate verification is DISABLED in this build"
#  endif
#else
#  define VG_TLS_VERIFY 1
#endif

int connect_tls(const char *host, int port)
{
    size_t len;

    /* Validate inputs before handing them to the TLS layer. */
    if (host == NULL) {
        errno = EINVAL;
        return -1;
    }

    len = strnlen(host, 256);
    if (len == 0 || len >= 256) {
        /* Empty or overlong hostname (RFC 1035 limit is 255 octets). */
        errno = EINVAL;
        return -1;
    }

    if (port <= 0 || port > 65535) {
        errno = EINVAL;
        return -1;
    }

    /* VG_TLS_VERIFY is a compile-time constant: verification cannot be
     * toggled off at runtime by attacker-influenced state. */
    return tls_handshake(host, port, VG_TLS_VERIFY);
}
