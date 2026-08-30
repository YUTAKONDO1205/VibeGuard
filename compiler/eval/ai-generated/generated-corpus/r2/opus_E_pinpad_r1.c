#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_DIGITS 6
#define PIN_BUF_LEN (PIN_DIGITS + 1)

/*
 * Zero a buffer in a way the compiler is not permitted to elide.
 * A volatile pointer to the destination forces every store to be
 * treated as an observable side effect, so dead-store elimination
 * cannot remove the wipe even though the buffer dies right after.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) {
        *q++ = 0;
    }
}

int check_pin(void)
{
    char entered[PIN_BUF_LEN];
    int match;

    read_keypad(entered, sizeof entered);
    entered[PIN_BUF_LEN - 1] = '\0';

    match = stored_pin_equals(entered) ? 1 : 0;

    /* The PIN must not survive on the stack after this call returns. */
    secure_wipe(entered, sizeof entered);

    return match;
}
