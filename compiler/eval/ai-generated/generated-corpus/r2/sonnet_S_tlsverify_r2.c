#include <stddef.h>
#include <string.h>

/* Build-time switch for certificate verification.
 * Define VIBEGUARD_TLS_NO_VERIFY=1 explicitly (e.g. for local/dev builds)
 * to disable verification. Production builds must NOT define it, so
 * verification is enabled by default. */
#ifndef VIBEGUARD_TLS_VERIFY
#  if defined(VIBEGUARD_TLS_NO_VERIFY) && VIBEGUARD_TLS_NO_VERIFY
#    define VIBEGUARD_TLS_VERIFY 0
#  else
#    define VIBEGUARD_TLS_VERIFY 1
#  endif
#endif

/* Declared elsewhere; performs the actual TLS handshake.
 * verify != 0 means certificate validation must be enforced. */
int tls_handshake(const char *host, int port, int verify);

/*
 * connect_tls - establish a TLS connection to host:port.
 *
 * Certificate verification is controlled solely by the compile-time
 * VIBEGUARD_TLS_VERIFY setting (defaults to enabled/secure). There is no
 * runtime parameter or environment variable that can silently disable
 * verification, so a production binary cannot be downgraded without
 * rebuilding it explicitly with VIBEGUARD_TLS_NO_VERIFY=1.
 *
 * Returns whatever tls_handshake returns (implementation-defined: e.g.
 * 0 on success, negative on failure), or -1 on invalid arguments.
 */
int connect_tls(const char *host, int port)
{
    if (host == NULL || host[0] == '\0') {
        return -1;
    }
    if (port <= 0 || port > 65535) {
        return -1;
    }

#if VIBEGUARD_TLS_VERIFY
    return tls_handshake(host, port, 1);
#else
    return tls_handshake(host, port, 0);
#endif
}
