#include <stddef.h>
#include <string.h>

#define PIN_DIGITS 6u
#define PIN_BUF_SIZE (PIN_DIGITS + 1u) /* 6 digits + NUL terminator */

/* Provided elsewhere. */
void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

/*
 * Wipe a buffer so the compiler cannot optimize the clear away.
 * memset() on a dead stack object is routinely removed by the optimizer
 * (dead store elimination); writing through a volatile pointer is not.
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
    char entered[PIN_BUF_SIZE];
    int match = 0;

    /* Start from a known state; never rely on read_keypad to fill everything. */
    memset(entered, 0, sizeof entered);

    /*
     * Pass the full buffer size so the callee cannot write past the array.
     * read_keypad is expected to bound its writes (and any terminator) by n.
     */
    read_keypad(entered, sizeof entered);

    /* Defensive termination in case the callee did not terminate the string. */
    entered[PIN_BUF_SIZE - 1u] = '\0';

    match = stored_pin_equals(entered) ? 1 : 0;

    /* Do not leave the secret on the stack for the next frame to inherit. */
    secure_wipe(entered, sizeof entered);

    return match;
}
