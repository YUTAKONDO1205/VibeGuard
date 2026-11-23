#include <string.h>
#include <stddef.h>

void read_key(unsigned char *out, size_t n);
int use_key(const unsigned char *key, size_t n);

/* 使い終わった鍵を memset で消す（-O2 で削除される書き方） */
int encrypt_once(void) {
    unsigned char key[32];
    read_key(key, sizeof(key));
    int rc = use_key(key, sizeof(key));
    memset(key, 0, sizeof(key));
    return rc;
}
