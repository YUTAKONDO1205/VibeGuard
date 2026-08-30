#include <stdio.h>
#include <stddef.h>

/* Provided elsewhere: performs the TLS handshake.
 * verify != 0  -> full certificate chain and hostname verification
 * verify == 0  -> verification disabled (INSECURE)
 * Returns a connected socket fd on success, or a negative value on failure. */
int tls_handshake(const char *host, int port, int verify);

/*
 * Certificate verification policy.
 *
 * Verification is ON by default. It can only be turned off by a build that
 * *both* defines VIBEGUARD_ALLOW_INSECURE_TLS and is a non-production build
 * (NDEBUG not defined). A production build (-DNDEBUG) therefore keeps
 * verification enabled no matter what else is defined on the command line.
 */
#if defined(VIBEGUARD_ALLOW_INSECURE_TLS) && !defined(NDEBUG)
#define TLS_VERIFY_PEER 0
#warning "TLS certificate verification is DISABLED. Development builds only."
#else
#define TLS_VERIFY_PEER 1
#endif

/* Compile-time assertion: in a production build the policy must be "verify".
 * If someone tries to ship with verification off, the build fails instead of
 * silently producing an insecure binary. */
#if defined(NDEBUG)
typedef char tls_verify_required_in_production[(TLS_VERIFY_PEER == 1) ? 1 : -1];
#endif

int connect_tls(const char *host, int port)
{
    int verify = TLS_VERIFY_PEER;
    int fd;

    if (host == NULL || host[0] == '\0') {
        return -1;
    }
    if (port <= 0 || port > 65535) {
        return -1;
    }

    if (!verify) {
        /* Loud, unconditional runtime notice; never reachable in a
         * production (NDEBUG) build because of the check above. */
        fprintf(stderr,
                "SECURITY WARNING: TLS certificate verification is disabled "
                "for %s:%d. Do not use this build in production.\n",
                host, port);
    }

    fd = tls_handshake(host, port, verify);
    if (fd < 0) {
        return -1;
    }

    return fd;
}
