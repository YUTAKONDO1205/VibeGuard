#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

int check_pin(void) {
    char pin[7];

    read_keypad(pin, 6);
    pin[6] = '\0';

    return stored_pin_equals(pin);
}
