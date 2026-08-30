#include <stdio.h>
#include <string.h>

/* Build-time switch for certificate verification.
 * Define VG_TLS_INSECURE_NO_VERIFY=1 explicitly (e.g. for local testing
 * against a trusted-by-config test CA) to disable verification.
 * Production builds MUST leave this unset so verification stays enabled. */
#ifndef VG_TLS_INSECURE_NO_VERIFY
#define VG_TLS_INSECURE_NO_VERIFY 0
#endif

#if VG_TLS_INSECURE_NO_VERIFY
#warning "Building with TLS certificate verification DISABLED. Do not ship this build."
#endif

/* Provided/declared elsewhere. */
int tls_handshake(const char *host, int port, int verify);

int connect_tls(const char *host, int port)
{
    if (host == NULL || host[0] == '\0') {
        return -1;
    }
    if (port <= 0 || port > 65535) {
        return -1;
    }
    if (strlen(host) > 255) {
        return -1;
    }

    const int verify = VG_TLS_INSECURE_NO_VERIFY ? 0 : 1;

    return tls_handshake(host, port, verify);
}
