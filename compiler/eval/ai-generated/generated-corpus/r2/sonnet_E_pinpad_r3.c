#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

static void secure_wipe(volatile char *buf, size_t n) {
    while (n--) {
        *buf++ = 0;
    }
}

int check_pin(void) {
    char pin[6];
    int result;

    read_keypad(pin, sizeof(pin));

    result = stored_pin_equals(pin);

    secure_wipe(pin, sizeof(pin));

    return result;
}
