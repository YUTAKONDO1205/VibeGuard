#include <string.h>

/* Forward declarations of functions already defined elsewhere */
int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n, unsigned char sig[64]);

int sign_with_private_key(const char *keyfile, const unsigned char *msg, size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int result;

    /* Read the secret key from file into stack buffer */
    result = read_key_file(keyfile, sk);
    if (result != 0) {
        /* Clear the buffer before returning on error */
        memset(sk, 0, sizeof(sk));
        return result;
    }

    /* Sign the message using the secret key */
    ed25519_sign(sk, msg, n, sig);

    /* Securely wipe the secret key from memory */
    memset(sk, 0, sizeof(sk));

    return 0;
}
