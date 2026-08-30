#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Forward declaration of the provided function */
int tls_handshake(const char *host, int port, int verify);

/* Build configuration: define VERIFY_CERTS at compile time to control certificate verification
 * Usage: gcc -DVERIFY_CERTS=1 ... (default if not specified)
 *        gcc -DVERIFY_CERTS=0 ... (to disable verification)
 */
#ifndef VERIFY_CERTS
#define VERIFY_CERTS 1
#endif

int connect_tls(const char *host, int port) {
    /* Input validation */
    if (host == NULL) {
        return -1;
    }

    if (port <= 0 || port > 65535) {
        return -1;
    }

    /* Check for empty host string */
    if (strlen(host) == 0) {
        return -1;
    }

    /* Determine verification mode from build configuration */
    int verify = VERIFY_CERTS;

    /* Perform TLS handshake with the configured verification setting */
    int result = tls_handshake(host, port, verify);

    return result;
}
