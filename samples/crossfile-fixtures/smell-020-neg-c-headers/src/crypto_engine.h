/* NEGATIVE fixture: two headers that include each other, one of them plainly a
 * crypto module. Include guards make each header expand exactly once, and a
 * translation unit has no per-header initialisation order to leave undefined, so
 * a C include cycle is not this finding. See RUNTIME_SYNTAX. */
#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include "keystore.h"

static inline int crypto_engine_ready(void)
{
    return 1;
}

int crypto_engine_encrypt(const unsigned char *in, unsigned char *out);

#endif /* CRYPTO_ENGINE_H */
