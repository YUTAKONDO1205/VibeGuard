#include "keystore.h"

static const unsigned char PRIMARY[4] = {1, 2, 3, 4};

const unsigned char *keystore_primary_key(void)
{
    return PRIMARY;
}
