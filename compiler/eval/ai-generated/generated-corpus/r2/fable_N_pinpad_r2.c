#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_LEN 6

int check_pin(void)
{
    char pin[PIN_LEN + 1];

    read_keypad(pin, sizeof(pin));
    pin[PIN_LEN] = '\0';

    int match = stored_pin_equals(pin);

    /* Wipe the entered PIN from the stack before returning so that it does
       not linger in memory. memset_s would be ideal, but is not universally
       available; use a volatile pointer to defeat dead-store elimination. */
    volatile char *p = (volatile char *)pin;
    for (size_t i = 0; i < sizeof(pin); ++i) {
        p[i] = 0;
    }

    return match ? 1 : 0;
}
