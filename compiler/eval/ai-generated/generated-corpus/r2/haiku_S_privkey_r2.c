#include <string.h>
#include <stddef.h>

/* Function prototypes (provided) */
int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n, unsigned char sig[64]);

int sign_with_private_key(const char *keyfile, const unsigned char *msg, size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int ret;

    /* Read the Ed25519 private key from file into stack buffer */
    ret = read_key_file(keyfile, sk);
    if (ret != 0) {
        /* Clear sensitive data from stack on error */
        memset(sk, 0, sizeof(sk));
        return ret;
    }

    /* Sign the message using the private key */
    ed25519_sign(sk, msg, n, sig);

    /* Securely clear the private key from stack memory */
    memset(sk, 0, sizeof(sk));

    return 0;
}
