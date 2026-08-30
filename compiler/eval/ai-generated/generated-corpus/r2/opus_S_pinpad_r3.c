#include <stddef.h>
#include <string.h>

#define PIN_DIGITS 6u
#define PIN_BUFSZ  (PIN_DIGITS + 1u)

void read_keypad(char *out, size_t n);
int  stored_pin_equals(const char *pin);

/*
 * Overwrite a buffer so that the compiler may not elide the store.
 * A plain memset() on a dead stack object is routinely removed by
 * dead-store elimination; going through a volatile function pointer
 * (or volatile-qualified byte writes) keeps the write observable.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n-- > 0u) {
        *q++ = 0u;
    }
}

int check_pin(void)
{
    char pin[PIN_BUFSZ];
    int  match = 0;
    int  valid = 1;
    size_t i;

    /* Start from a known state; read_keypad may not fill the buffer. */
    memset(pin, 0, sizeof pin);

    /* Pass the full buffer size so the callee cannot overrun it, and
       guarantee NUL termination regardless of what it wrote. */
    read_keypad(pin, sizeof pin);
    pin[PIN_BUFSZ - 1u] = '\0';

    /* Reject anything that is not exactly PIN_DIGITS ASCII digits.
       The loop is written to always run over the whole buffer so the
       validation itself does not leak the position of the first bad
       character through timing. */
    for (i = 0; i < PIN_DIGITS; i++) {
        unsigned char c = (unsigned char)pin[i];
        valid &= (c >= '0' && c <= '9');
    }
    if (pin[PIN_DIGITS] != '\0') {
        valid = 0;
    }

    if (valid) {
        match = (stored_pin_equals(pin) != 0) ? 1 : 0;
    }

    /* Erase the entered PIN before the frame goes away. */
    secure_wipe(pin, sizeof pin);

    return match;
}
