/*
 * connect_tls: establish a TLS connection to host:port.
 *
 * Certificate verification policy
 * -------------------------------
 * Verification is ON. It can only be turned off by a build that explicitly
 * opts in with BOTH of the following defined at compile time:
 *
 *     -DVG_TLS_ALLOW_INSECURE_BUILD=1   (the escape hatch is compiled in)
 *     -DVG_TLS_INSECURE_NO_VERIFY=1     (and it is actually taken)
 *
 * The two-key design is deliberate: a single stray -D in a Makefile cannot
 * silently disable verification, and the escape hatch cannot exist at all in
 * a release build (see the NDEBUG guard below, which makes an insecure
 * release build a compile-time error).
 *
 * There is no runtime switch, no environment variable, and no argument that
 * can lower verification: an insecure configuration must be visible in the
 * build command that produced the binary.
 */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Declared elsewhere. verify != 0 means "verify the peer certificate". */
int tls_handshake(const char *host, int port, int verify);

/* ---- build-time policy resolution ------------------------------------- */

#if defined(VG_TLS_INSECURE_NO_VERIFY) && (VG_TLS_INSECURE_NO_VERIFY + 0)
#  if !defined(VG_TLS_ALLOW_INSECURE_BUILD) || !(VG_TLS_ALLOW_INSECURE_BUILD + 0)
#    error "VG_TLS_INSECURE_NO_VERIFY requires VG_TLS_ALLOW_INSECURE_BUILD=1."
#  endif
#  if defined(NDEBUG)
#    error "Certificate verification cannot be disabled in a release build."
#  endif
#  define VG_TLS_VERIFY_PEER 0
#else
#  define VG_TLS_VERIFY_PEER 1
#endif

#if !VG_TLS_VERIFY_PEER
#  if defined(__GNUC__) || defined(__clang__)
#    warning "INSECURE BUILD: TLS certificate verification is DISABLED."
#  endif
#endif

/* ---- errors ------------------------------------------------------------ */

#define TLS_OK              0
#define TLS_ERR_ARG       (-1)   /* bad host or port                        */
#define TLS_ERR_HANDSHAKE (-2)   /* handshake or verification failed        */

/* Hostnames are bounded; anything longer cannot be a valid DNS name. */
#define TLS_MAX_HOST_LEN 253

/*
 * Accept only what can be a DNS hostname or an IP literal: letters, digits,
 * '-', '.', ':' (IPv6) and '_'. Rejecting everything else keeps control
 * characters, CR/LF, NUL-embedding tricks, whitespace and shell/URL
 * metacharacters out of whatever the transport layer does with the name.
 */
static int host_char_ok(unsigned char c)
{
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= '0' && c <= '9') return 1;
    return c == '-' || c == '.' || c == ':' || c == '_';
}

static int host_is_valid(const char *host)
{
    size_t len;
    size_t i;

    if (host == NULL)
        return 0;

    /* Bounded scan: never walk past TLS_MAX_HOST_LEN even if unterminated. */
    len = strnlen(host, (size_t)TLS_MAX_HOST_LEN + 1);
    if (len == 0 || len > (size_t)TLS_MAX_HOST_LEN)
        return 0;

    /* No leading/trailing dot, no empty label. */
    if (host[0] == '.' || host[len - 1] == '.')
        return 0;

    for (i = 0; i < len; i++) {
        if (!host_char_ok((unsigned char)host[i]))
            return 0;
        if (i > 0 && host[i] == '.' && host[i - 1] == '.')
            return 0;
    }
    return 1;
}

/* ---- public entry point ------------------------------------------------ */

int connect_tls(const char *host, int port)
{
    const int verify = VG_TLS_VERIFY_PEER;
    int rc;

    if (!host_is_valid(host))
        return TLS_ERR_ARG;

    if (port < 1 || port > 65535)
        return TLS_ERR_ARG;

    if (!verify) {
        /*
         * Loud, unconditional runtime notice. An insecure build must never be
         * mistakable for a secure one while it is running.
         */
        fprintf(stderr,
                "SECURITY WARNING: TLS certificate verification is DISABLED "
                "in this build; the connection to %s:%d is not authenticated "
                "and is trivially interceptable.\n",
                host, port);
    }

    rc = tls_handshake(host, port, verify);
    if (rc != 0) {
        /*
         * Fail closed: a failed handshake (including a rejected certificate)
         * is never retried with verification relaxed.
         */
        return TLS_ERR_HANDSHAKE;
    }

    return TLS_OK;
}
