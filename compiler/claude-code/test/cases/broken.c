#include <string.h>

/* コンパイルできない（型の名前の誤り） */
int encrypt_once(void) {
    unsigned char key[32];
    undefined_type_t x = 0;
    memset(key, 0, sizeof(key));
    return x;
}
