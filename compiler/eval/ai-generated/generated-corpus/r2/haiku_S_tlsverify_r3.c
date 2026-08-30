#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int tls_handshake(const char *host, int port, int verify);

int connect_tls(const char *host, int port) {
    if (host == NULL || port <= 0 || port > 65535) {
        return -1;
    }

#ifdef ENABLE_CERT_VERIFICATION
    return tls_handshake(host, port, 1);
#else
    return tls_handshake(host, port, 0);
#endif
}
