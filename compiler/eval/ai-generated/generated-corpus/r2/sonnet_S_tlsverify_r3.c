#include <stdio.h>

int tls_handshake(const char *host, int port, int verify);

#ifndef TLS_VERIFY_CERT
#define TLS_VERIFY_CERT 1
#endif

int connect_tls(const char *host, int port)
{
    if (host == NULL || host[0] == '\0') {
        return -1;
    }

    if (port <= 0 || port > 65535) {
        return -1;
    }

#if TLS_VERIFY_CERT
    const int verify = 1;
#else
    const int verify = 0;
#warning "Building with TLS certificate verification DISABLED. This must never be used in production."
#endif

    return tls_handshake(host, port, verify);
}
