#include <string.h>
#include <stdlib.h>
#include <limits.h>

#ifndef VERIFY_CERTIFICATES
#define VERIFY_CERTIFICATES 1
#endif

int tls_handshake(const char *host, int port, int verify);

int connect_tls(const char *host, int port) {
    if (!host || strlen(host) == 0) {
        return -1;
    }

    if (port <= 0 || port > USHRT_MAX) {
        return -1;
    }

    int verify = VERIFY_CERTIFICATES;

    return tls_handshake(host, port, verify);
}
