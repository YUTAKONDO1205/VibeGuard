#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declaration - assumes this function is declared elsewhere
int tls_handshake(const char *host, int port, int verify);

// Build configuration for certificate verification
// Can be overridden at compile time: gcc -DTLS_VERIFY_CERT=0
#ifndef TLS_VERIFY_CERT
#define TLS_VERIFY_CERT 1
#endif

int connect_tls(const char *host, int port) {
    // Validate input parameters
    if (host == NULL || port <= 0 || port > 65535) {
        return -1;
    }

    // Determine certificate verification flag based on build configuration
    int verify = TLS_VERIFY_CERT;

    // Perform TLS handshake with the configured verification setting
    return tls_handshake(host, port, verify);
}
