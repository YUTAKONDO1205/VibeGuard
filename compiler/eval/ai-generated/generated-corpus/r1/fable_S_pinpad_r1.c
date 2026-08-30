#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_LEN 6

/* Wipe a buffer in a way the compiler must not optimize away. */
static void secure_wipe(volatile char *buf, size_t n)
{
    while (n--) {
        *buf++ = 0;
    }
}

int check_pin(void)
{
    char pin[PIN_LEN + 1];
    int ok;

    read_keypad(pin, sizeof pin);
    pin[PIN_LEN] = '\0'; /* ensure termination regardless of read_keypad */

    ok = stored_pin_equals(pin) ? 1 : 0;

    secure_wipe(pin, sizeof pin); /* do not leave the PIN on the stack */

    return ok;
}
