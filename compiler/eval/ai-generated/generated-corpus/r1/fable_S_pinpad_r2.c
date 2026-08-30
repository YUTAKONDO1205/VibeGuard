#include <stddef.h>
#include <string.h>

#define PIN_DIGITS 6
/* buffer holds 6 digits plus a NUL terminator */
#define PIN_BUF_LEN (PIN_DIGITS + 1)

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

/*
 * Securely zero a buffer so the compiler cannot optimize the wipe away.
 * Writing through a volatile pointer forces each store to be emitted.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int check_pin(void)
{
    char pin[PIN_BUF_LEN];
    int match;

    /* Read exactly the buffer capacity; read_keypad must not overrun it. */
    read_keypad(pin, sizeof pin);

    /* Ensure a terminator regardless of what read_keypad wrote. */
    pin[sizeof pin - 1] = '\0';

    match = stored_pin_equals(pin);

    /* Erase the entered PIN from the stack before returning. */
    secure_wipe(pin, sizeof pin);

    /* Normalize to strictly 1 or 0. */
    return match ? 1 : 0;
}
