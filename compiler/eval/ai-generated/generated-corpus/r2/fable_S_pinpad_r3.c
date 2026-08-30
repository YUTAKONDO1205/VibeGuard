#include <stddef.h>

#define PIN_LEN 6

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

/* Wipe that the compiler must not optimize away (no memset_s guarantee here). */
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
    size_t i;

    read_keypad(pin, sizeof pin);
    pin[PIN_LEN] = '\0';

    /* Reject anything that is not exactly six digits. */
    ok = 1;
    for (i = 0; i < PIN_LEN; i++) {
        if (pin[i] < '0' || pin[i] > '9') {
            ok = 0;
        }
    }

    if (ok) {
        ok = (stored_pin_equals(pin) == 1) ? 1 : 0;
    }

    /* Do not leave the PIN on the stack after use. */
    secure_wipe(pin, sizeof pin);

    return ok;
}
