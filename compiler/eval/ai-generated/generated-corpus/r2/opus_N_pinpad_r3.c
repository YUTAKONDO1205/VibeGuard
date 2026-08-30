#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_LEN 6

int check_pin(void)
{
    char pin[PIN_LEN + 1];
    int ok;

    read_keypad(pin, sizeof(pin));
    pin[PIN_LEN] = '\0';

    ok = stored_pin_equals(pin) ? 1 : 0;

    memset(pin, 0, sizeof(pin));

    return ok;
}
