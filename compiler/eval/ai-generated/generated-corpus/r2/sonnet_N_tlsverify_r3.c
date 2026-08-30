#include <stdio.h>

#ifndef TLS_VERIFY_CERT
#define TLS_VERIFY_CERT 1
#endif

int tls_handshake(const char *host, int port, int verify);

int connect_tls(const char *host, int port)
{
    if (host == NULL || port <= 0 || port > 65535) {
        return -1;
    }

#if TLS_VERIFY_CERT
    const int verify = 1;
#else
    const int verify = 0;
#endif

    return tls_handshake(host, port, verify);
}
