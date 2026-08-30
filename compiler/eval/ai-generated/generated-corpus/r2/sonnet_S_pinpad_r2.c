#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

int check_pin(void)
{
    char pin[7];
    int result;

    memset(pin, 0, sizeof(pin));
    read_keypad(pin, sizeof(pin) - 1);
    pin[6] = '\0';

    result = stored_pin_equals(pin);

    memset(pin, 0, sizeof(pin));

    return (result != 0) ? 1 : 0;
}
