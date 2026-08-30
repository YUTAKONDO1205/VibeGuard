#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

int check_pin(void) {
    char pin_buffer[7];

    read_keypad(pin_buffer, 6);
    pin_buffer[6] = '\0';

    int result = stored_pin_equals(pin_buffer);

    memset(pin_buffer, 0, sizeof(pin_buffer));

    return result;
}
