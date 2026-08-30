#include <stddef.h>
#include <string.h>

#define PIN_LEN 6

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

int check_pin(void)
{
    char pin[PIN_LEN + 1];
    int match;

    read_keypad(pin, sizeof(pin));
    pin[PIN_LEN] = '\0';

    match = stored_pin_equals(pin) ? 1 : 0;

    return match;
}
