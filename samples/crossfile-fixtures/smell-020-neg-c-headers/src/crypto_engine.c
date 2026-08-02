#include "crypto_engine.h"

int crypto_engine_encrypt(const unsigned char *in, unsigned char *out)
{
    out[0] = in[0] ^ keystore_primary_key()[0];
    return 0;
}
