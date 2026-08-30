#include <stdio.h>
#include <string.h>
#include <errno.h>

/* Provided by the TLS backend. verify != 0 requests full certificate and
 * hostname verification. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification policy.
 *
 * Verification is ON unless the build explicitly opts out by defining
 * VIBEGUARD_TLS_INSECURE_NO_VERIFY. The opt-out is deliberately hard to
 * trigger by accident:
 *   - it must be defined explicitly at configure time,
 *   - it is rejected outright in release builds (NDEBUG),
 *   - it emits a compile-time warning so it cannot slip through review.
 *
 * The default (no macro defined) is always the secure one, so a missing or
 * misspelled build flag fails closed rather than open.
 */
#if defined(VIBEGUARD_TLS_INSECURE_NO_VERIFY)
#  if defined(NDEBUG)
#    error "VIBEGUARD_TLS_INSECURE_NO_VERIFY must never be enabled in a release build"
#  endif
#  if defined(__GNUC__) || defined(__clang__)
#    warning "TLS certificate verification is DISABLED: development builds only"
#  endif
#  define TLS_VERIFY_PEER 0
#else
#  define TLS_VERIFY_PEER 1
#endif

/* Conservative bound on a DNS name (253 chars + NUL). */
#define TLS_MAX_HOST_LEN 253

static int host_is_valid(const char *host)
{
    size_t len;
    size_t i;

    if (host == NULL) {
        return 0;
    }

    len = strnlen(host, TLS_MAX_HOST_LEN + 1);
    if (len == 0 || len > TLS_MAX_HOST_LEN) {
        return 0;
    }

    /* Reject anything that is not a plausible hostname/IP literal character.
     * This keeps embedded NULs, CR/LF, spaces and separators out of the name
     * that will be matched against the certificate. */
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)host[i];
        int ok = (c >= 'a' && c <= 'z') ||
                 (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') ||
                 c == '.' || c == '-' || c == ':';
        if (!ok) {
            return 0;
        }
    }

    /* No leading/trailing dot or hyphen, and no empty labels. */
    if (host[0] == '.' || host[0] == '-' ||
        host[len - 1] == '.' || host[len - 1] == '-') {
        return 0;
    }
    if (strstr(host, "..") != NULL) {
        return 0;
    }

    return 1;
}

/*
 * Connect to host:port over TLS.
 *
 * Returns the handshake result (>= 0 on success as defined by the backend),
 * or -1 on invalid arguments.
 */
int connect_tls(const char *host, int port)
{
    const int verify = TLS_VERIFY_PEER;

    if (!host_is_valid(host)) {
        errno = EINVAL;
        return -1;
    }

    if (port < 1 || port > 65535) {
        errno = EINVAL;
        return -1;
    }

    if (!verify) {
        /* Loud, per-connection runtime notice: an unverified peer is not a
         * secure channel, and the operator must be able to see it in logs. */
        fprintf(stderr,
                "WARNING: TLS certificate verification disabled for %s:%d "
                "(insecure development build)\n",
                host, port);
    }

    return tls_handshake(host, port, verify);
}
