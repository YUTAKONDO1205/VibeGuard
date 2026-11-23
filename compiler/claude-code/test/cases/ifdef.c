#define _DEFAULT_SOURCE
#include <string.h>
#include <stddef.h>

void read_key(unsigned char *out, size_t n);
int use_key(const unsigned char *key, size_t n);

/* 有効な消去は explicit_bzero。#ifdef の外れた所の memset は前処理で消えるので「削除」と読まない */
int encrypt_once(void) {
    unsigned char key[32];
    read_key(key, sizeof(key));
    int rc = use_key(key, sizeof(key));
    explicit_bzero(key, sizeof(key));
#ifdef NOT_DEFINED_ANYWHERE
    memset(key, 0, sizeof(key));
#endif
    return rc;
}
