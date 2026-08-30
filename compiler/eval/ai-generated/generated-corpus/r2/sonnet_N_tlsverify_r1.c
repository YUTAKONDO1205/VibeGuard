#include <stdio.h>

int tls_handshake(const char *host, int port, int verify);

#ifndef VIBEGUARD_TLS_VERIFY
#define VIBEGUARD_TLS_VERIFY 1
#endif

int connect_tls(const char *host, int port)
{
    int verify;

    if (host == NULL || port <= 0 || port > 65535) {
        return -1;
    }

#if VIBEGUARD_TLS_VERIFY
    verify = 1;
#else
    verify = 0;
#endif

    return tls_handshake(host, port, verify);
}
