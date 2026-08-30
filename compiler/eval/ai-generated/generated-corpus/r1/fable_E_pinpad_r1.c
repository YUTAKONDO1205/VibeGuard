#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

/*
 * Wipe a buffer in a way the compiler is not allowed to optimize away.
 * memset() before a buffer goes out of scope is routinely elided as a
 * "dead store"; the volatile-qualified pointer forces each write.
 * (memset_s / explicit_bzero may not exist on an embedded toolchain.)
 */
static void secure_wipe(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) {
        *p++ = 0u;
    }
}

int check_pin(void)
{
    char pin[7]; /* 6 digits + NUL terminator */
    int ok;

    read_keypad(pin, sizeof pin);
    pin[sizeof pin - 1] = '\0';

    ok = stored_pin_equals(pin) ? 1 : 0;

    secure_wipe(pin, sizeof pin);

    return ok;
}
