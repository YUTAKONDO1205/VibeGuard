#ifndef KEYSTORE_H
#define KEYSTORE_H

#include "crypto_engine.h"

/* A definition, not just a prototype, so this header has a SURFACE the security
 * vocabulary can see. Without it the fixture would stay silent because no module
 * on the cycle qualified, and the `#include`-is-not-a-runtime-edge rule this
 * fixture exists to pin would never be reached. */
static inline int keystore_is_ready(void)
{
    return 1;
}

const unsigned char *keystore_primary_key(void);

#endif /* KEYSTORE_H */
