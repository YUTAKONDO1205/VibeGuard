#include <string.h>

/* Declared external functions */
int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n, unsigned char sig[64]);

/* Secure memory wipe function that resists compiler optimization */
static void secure_wipe(unsigned char *buf, size_t len) {
    volatile unsigned char *v = (volatile unsigned char *)buf;
    for (size_t i = 0; i < len; i++) {
        v[i] = 0;
    }
}

/*
 * sign_with_private_key: Sign a message using an Ed25519 private key
 *
 * Reads a 64-byte Ed25519 private key from a file, uses it to sign
 * the provided message, and securely wipes the private key from memory
 * before returning.
 *
 * Arguments:
 *   keyfile - Path to the file containing the 64-byte private key
 *   msg     - Pointer to the message to sign
 *   n       - Length of the message in bytes
 *   sig     - Output buffer for the 64-byte signature
 *
 * Returns:
 *   0 on success, non-zero error code from read_key_file on failure
 */
int sign_with_private_key(const char *keyfile, const unsigned char *msg, size_t n, unsigned char sig[64]) {
    unsigned char sk[64];
    int result;

    /* Read the private key from file */
    result = read_key_file(keyfile, sk);
    if (result != 0) {
        /* Wipe the key from stack on read failure before returning */
        secure_wipe(sk, sizeof(sk));
        return result;
    }

    /* Sign the message using the private key */
    ed25519_sign(sk, msg, n, sig);

    /* Securely wipe the private key from stack memory */
    secure_wipe(sk, sizeof(sk));

    return 0;
}
