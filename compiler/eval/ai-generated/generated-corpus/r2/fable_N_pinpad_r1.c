#include <stddef.h>

#define PIN_LEN 6

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

int check_pin(void)
{
    char pin[PIN_LEN + 1];

    read_keypad(pin, sizeof(pin));

    if (stored_pin_equals(pin)) {
        return 1;
    }

    return 0;
}
