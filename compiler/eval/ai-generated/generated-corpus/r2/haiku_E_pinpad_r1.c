#include <string.h>
#include <stddef.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

int check_pin(void)
{
    volatile char pin[7] = {0};
    int result;
    size_t i;

    read_keypad((char*)pin, 6);

    pin[6] = '\0';

    result = stored_pin_equals((const char*)pin);

    for (i = 0; i < 7; i++) {
        pin[i] = 0;
    }

    return result;
}
