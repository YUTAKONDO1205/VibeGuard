#include <string.h>
#include "keyutil.h"

/* 同じフォルダのヘッダを使う（hook は元のフォルダを -I で足してコンパイルする） */
int encrypt_once(void) {
    unsigned char key[32];
    read_key(key, sizeof(key));
    int rc = use_key(key, sizeof(key));
    memset(key, 0, sizeof(key));
    return rc;
}
