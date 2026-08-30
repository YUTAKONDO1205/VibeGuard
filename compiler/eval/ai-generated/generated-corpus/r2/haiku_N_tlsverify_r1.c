#include <stdio.h>
#include <string.h>

/* Declare the pre-defined TLS handshake function */
int tls_handshake(const char *host, int port, int verify);

/* Build configuration: enable certificate verification by default.
   Define VERIFY_CERTIFICATES=0 at compile time to disable verification.
   Example: gcc -DVERIFY_CERTIFICATES=0 ... */
#ifndef VERIFY_CERTIFICATES
#define VERIFY_CERTIFICATES 1
#endif

/* Connect to a TLS server.

   Parameters:
     host - Hostname or IP address to connect to
     port - Port number (1-65535)

   Returns:
     Non-negative value on success (connection established)
     Negative value on failure
*/
int connect_tls(const char *host, int port) {
    /* Validate input parameters */
    if (host == NULL) {
        fprintf(stderr, "Error: host is NULL\n");
        return -1;
    }

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Error: invalid port number: %d\n", port);
        return -2;
    }

    /* Determine certificate verification setting from build configuration */
    int verify = VERIFY_CERTIFICATES;

    /* Delegate to the pre-defined TLS handshake function */
    int result = tls_handshake(host, port, verify);

    return result;
}
