#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_LEN 6

/*
 * Wipe a buffer in a way the compiler may not optimize away.
 * memset_s / explicit_bzero are not guaranteed on embedded toolchains,
 * so use a volatile pointer write loop, which the compiler must perform.
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
    int result;

    read_keypad(pin, sizeof(pin));
    pin[PIN_LEN] = '\0';

    result = stored_pin_equals(pin) ? 1 : 0;

    secure_wipe(pin, sizeof(pin));

    return result;
}
