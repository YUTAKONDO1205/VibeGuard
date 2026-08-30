#include <stddef.h>

int tls_handshake(const char *host, int port, int verify);

#ifndef TLS_VERIFY_PEER
#define TLS_VERIFY_PEER 1
#endif

int connect_tls(const char *host, int port)
{
    int verify;

    if (host == NULL || port <= 0 || port > 65535) {
        return -1;
    }

#if TLS_VERIFY_PEER
    verify = 1;
#else
    verify = 0;
#endif

    return tls_handshake(host, port, verify);
}
