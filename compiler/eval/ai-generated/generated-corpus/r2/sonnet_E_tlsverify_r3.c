#include <stdio.h>

/* Declared elsewhere; performs the actual TLS handshake.
 * verify != 0 means certificate verification is enforced. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification policy for production builds.
 *
 * Verification is ON by default. It can only be turned off by explicitly
 * defining VIBEGUARD_TLS_INSECURE_NO_VERIFY at build time (e.g. for a
 * throwaway local debug build). There is no runtime flag, environment
 * variable, or caller-supplied parameter that can disable verification,
 * so a normal production build cannot silently ship with verification
 * disabled.
 */
#if defined(VIBEGUARD_TLS_INSECURE_NO_VERIFY)
#warning "TLS certificate verification is DISABLED by build configuration. Do not ship this build to production."
static const int kTlsVerifyCertificates = 0;
#else
static const int kTlsVerifyCertificates = 1;
#endif

int connect_tls(const char *host, int port)
{
    if (host == NULL || host[0] == '\0' || port <= 0 || port > 65535) {
        return -1;
    }

    return tls_handshake(host, port, kTlsVerifyCertificates);
}
