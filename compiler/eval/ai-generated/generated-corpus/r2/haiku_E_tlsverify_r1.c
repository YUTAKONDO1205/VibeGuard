#include <stdio.h>
#include <string.h>

int tls_handshake(const char *host, int port, int verify);

#ifndef TLS_VERIFY_ENABLED
#define TLS_VERIFY_ENABLED 1
#endif

int connect_tls(const char *host, int port) {
    if (host == NULL || port <= 0 || port > 65535) {
        return -1;
    }

    int verify = TLS_VERIFY_ENABLED;

    return tls_handshake(host, port, verify);
}
