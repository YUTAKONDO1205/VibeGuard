#include <stdio.h>
#include <stddef.h>

/* Declared elsewhere. Returns a connected socket/handle on success,
 * or a negative value on failure. The third argument selects whether
 * the peer certificate chain and hostname are verified. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification policy.
 *
 * Verification is ENABLED by default and must stay on for any real
 * deployment. It can only be turned off at build time by explicitly
 * defining VIBEGUARD_TLS_INSECURE_NO_VERIFY (for example, a local test
 * harness talking to a throwaway self-signed endpoint).
 *
 * We deliberately do NOT expose a runtime flag or environment variable
 * to disable verification: an attacker who can influence the process
 * environment could otherwise silently strip TLS authentication and
 * mount a man-in-the-middle attack. Requiring a compile-time definition
 * keeps the insecure path out of shipped binaries.
 */
#if defined(VIBEGUARD_TLS_INSECURE_NO_VERIFY)
#  define VIBEGUARD_TLS_VERIFY 0
#  if defined(NDEBUG)
#    error "Refusing to build a release binary with TLS certificate verification disabled (VIBEGUARD_TLS_INSECURE_NO_VERIFY)."
#  endif
#else
#  define VIBEGUARD_TLS_VERIFY 1
#endif

int connect_tls(const char *host, int port)
{
    /* Reject obviously invalid inputs before touching the network. */
    if (host == NULL || host[0] == '\0') {
        return -1;
    }
    if (port <= 0 || port > 65535) {
        return -1;
    }

#if !VIBEGUARD_TLS_VERIFY
    /* Loud, unmissable trace so a mis-built binary cannot fail silently. */
    fprintf(stderr,
            "WARNING: connect_tls() is performing an UNVERIFIED TLS handshake "
            "to %s:%d. Certificate verification is disabled by build option "
            "VIBEGUARD_TLS_INSECURE_NO_VERIFY. Never use this in production.\n",
            host, port);
#endif

    /* Verification defaults to on; only a compile-time opt-out lowers it. */
    return tls_handshake(host, port, VIBEGUARD_TLS_VERIFY);
}
