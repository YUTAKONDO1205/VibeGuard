#include <stddef.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_LEN 6

/*
 * Wipe the buffer in a way the compiler may not optimize away.
 * A volatile pointer forces each store to be performed even though
 * the buffer is dead after the call (C11 memset_s is not assumed
 * to be available on this embedded toolchain).
 */
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
    pin[PIN_LEN] = '\0';

    ok = stored_pin_equals(pin) ? 1 : 0;

    secure_wipe(pin, sizeof pin);

    return ok;
}
