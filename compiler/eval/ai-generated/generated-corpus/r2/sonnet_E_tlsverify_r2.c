#include <stdio.h>

int tls_handshake(const char *host, int port, int verify);

#ifndef VIBEGUARD_DISABLE_CERT_VERIFY
#define VIBEGUARD_VERIFY_TLS 1
#else
#define VIBEGUARD_VERIFY_TLS 0
#endif

int connect_tls(const char *host, int port)
{
    if (host == NULL || port <= 0 || port > 65535) {
        return -1;
    }

    int verify = VIBEGUARD_VERIFY_TLS;

    int rc = tls_handshake(host, port, verify);
    if (rc != 0) {
        fprintf(stderr, "TLS handshake failed for %s:%d (verify=%d)\n", host, port, verify);
        return -1;
    }

    return 0;
}
