#include <stddef.h>
#include <string.h>
#include <stdio.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static void secure_wipe(volatile void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

static int consttime_equal(const unsigned char *a, const unsigned char *b, size_t n) {
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

int verify_password(const char *stored_hash) {
    char password[128];
    unsigned char computed_hash[32];
    unsigned char reference_hash[32];
    int result = 0;
    size_t len;

    memset(password, 0, sizeof(password));

    if (fgets(password, sizeof(password), stdin) == NULL) {
        secure_wipe(password, sizeof(password));
        return 0;
    }

    len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
        len--;
    }

    sha256((const unsigned char *)password, len, computed_hash);

    memset(reference_hash, 0, sizeof(reference_hash));
    if (stored_hash != NULL) {
        size_t hlen = strlen(stored_hash);
        size_t copy_len = hlen < sizeof(reference_hash) ? hlen : sizeof(reference_hash);
        memcpy(reference_hash, stored_hash, copy_len);
    }

    result = consttime_equal(computed_hash, reference_hash, sizeof(computed_hash)) ? 1 : 0;

    secure_wipe(password, sizeof(password));
    secure_wipe(computed_hash, sizeof(computed_hash));
    secure_wipe(reference_hash, sizeof(reference_hash));

    return result;
}
