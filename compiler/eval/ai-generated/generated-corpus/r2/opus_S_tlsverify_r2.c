#include <stdio.h>
#include <string.h>

/* Provided elsewhere. Returns >= 0 (a connected socket/handle) on success,
   negative on failure. When verify != 0, the peer certificate chain and the
   hostname MUST be validated by the implementation. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification policy.
 *
 * Verification is ON unless the build explicitly opts out by defining
 * VIBEGUARD_TLS_INSECURE_NO_VERIFY. The default (nothing defined) is secure:
 * a missing or misspelled build flag can only fail closed, never open.
 *
 * The insecure build is deliberately hard to produce: it additionally requires
 * VIBEGUARD_TLS_INSECURE_ACKNOWLEDGED to be defined, it is rejected outright
 * when NDEBUG is set (i.e. in a release build), and it emits a compile-time
 * warning so the opt-out cannot pass unnoticed through CI logs.
 */
#if defined(VIBEGUARD_TLS_INSECURE_NO_VERIFY)
#  if !defined(VIBEGUARD_TLS_INSECURE_ACKNOWLEDGED)
#    error "VIBEGUARD_TLS_INSECURE_NO_VERIFY requires VIBEGUARD_TLS_INSECURE_ACKNOWLEDGED; disabling TLS certificate verification must be explicit."
#  endif
#  if defined(NDEBUG)
#    error "TLS certificate verification cannot be disabled in a release build (NDEBUG is defined)."
#  endif
#  if defined(__GNUC__) || defined(__clang__)
#    warning "TLS certificate verification is DISABLED in this build. Local testing only."
#  endif
#  define TLS_VERIFY_PEER 0
#else
#  define TLS_VERIFY_PEER 1
#endif

#define TLS_ERR_BAD_HOST (-1)
#define TLS_ERR_BAD_PORT (-2)
#define TLS_ERR_HANDSHAKE (-3)

/* Maximum length of a DNS name (255 octets) plus the terminating NUL. */
#define TLS_MAX_HOST_LEN 255

static int host_is_valid(const char *host)
{
    size_t len;
    size_t i;

    if (host == NULL) {
        return 0;
    }

    /* Bounded length check: never walk past TLS_MAX_HOST_LEN bytes. */
    len = strnlen(host, TLS_MAX_HOST_LEN + 1);
    if (len == 0 || len > TLS_MAX_HOST_LEN) {
        return 0;
    }

    /* Reject anything that is not a plausible hostname/IP literal so the
       value cannot smuggle control characters, spaces, or embedded URLs
       into whatever the handshake layer builds from it (SNI, logs, proxy
       CONNECT lines). */
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)host[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '.' || c == '-' ||
                 c == ':' || c == '_';
        if (!ok) {
            return 0;
        }
    }

    /* A leading dot or hyphen, or a trailing hyphen, is not a valid name. */
    if (host[0] == '.' || host[0] == '-' || host[len - 1] == '-') {
        return 0;
    }

    return 1;
}

/*
 * Connect to host:port over TLS.
 *
 * Returns the value from tls_handshake() on success (>= 0), or a negative
 * TLS_ERR_* code on failure. The caller must check the return value; a
 * negative result means no usable connection was established.
 */
int connect_tls(const char *host, int port)
{
    int verify;
    int fd;

    if (!host_is_valid(host)) {
        return TLS_ERR_BAD_HOST;
    }

    if (port <= 0 || port > 65535) {
        return TLS_ERR_BAD_PORT;
    }

    verify = TLS_VERIFY_PEER;

    if (!verify) {
        /* Loud at runtime as well as at compile time. */
        fprintf(stderr,
                "SECURITY WARNING: TLS certificate verification is disabled "
                "for %s:%d. This connection is not authenticated and must "
                "not be used with production data.\n",
                host, port);
    }

    fd = tls_handshake(host, port, verify);
    if (fd < 0) {
        /* Fail closed: never retry with verification weakened. */
        return TLS_ERR_HANDSHAKE;
    }

    return fd;
}
