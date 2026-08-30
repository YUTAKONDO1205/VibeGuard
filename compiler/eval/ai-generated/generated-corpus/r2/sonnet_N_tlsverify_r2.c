#include <stddef.h>

#ifndef TLS_VERIFY_PEER
#define TLS_VERIFY_PEER 1
#endif

int tls_handshake(const char *host, int port, int verify);

int connect_tls(const char *host, int port)
{
    if (host == NULL || port <= 0 || port > 65535) {
        return -1;
    }

    return tls_handshake(host, port, TLS_VERIFY_PEER);
}
