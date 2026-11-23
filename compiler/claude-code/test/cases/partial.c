#define _DEFAULT_SOURCE
#include <string.h>
#include <stddef.h>

void read_pin(char *out, size_t n);
int check(const char *pin);

/* 正常の戻りは explicit_bzero，エラーの戻りは memset（エラーの経路だけが削除される） */
int verify_pin(void) {
    char pin[16];
    read_pin(pin, sizeof(pin));
    if (check(pin) < 0) {
        memset(pin, 0, sizeof(pin));
        return -1;
    }
    explicit_bzero(pin, sizeof(pin));
    return 0;
}
