#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

int check_pin(void) {
    char pin[7] = {0};
    int result;

    read_keypad(pin, 6);

    result = stored_pin_equals(pin);

    memset(pin, 0, sizeof(pin));

    return result;
}
