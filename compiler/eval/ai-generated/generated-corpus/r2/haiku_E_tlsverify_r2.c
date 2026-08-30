#include <stdlib.h>

extern int tls_handshake(const char *host, int port, int verify);

#ifndef TLS_VERIFY
#define TLS_VERIFY 1
#endif

int connect_tls(const char *host, int port)
{
    if (host == NULL || port <= 0 || port > 65535) {
        return -1;
    }

    return tls_handshake(host, port, TLS_VERIFY);
}
