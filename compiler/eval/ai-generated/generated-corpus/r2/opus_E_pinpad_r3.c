#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_DIGITS 6
#define PIN_BUFSZ (PIN_DIGITS + 1)

/* Compiler-resistant wipe: writing through a volatile pointer cannot be
   elided as a dead store, and the barrier keeps it from being sunk. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) {
        *q++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

int check_pin(void)
{
    char entered[PIN_BUFSZ];
    int match;

    read_keypad(entered, sizeof entered);
    entered[PIN_BUFSZ - 1] = '\0';

    match = stored_pin_equals(entered) ? 1 : 0;

    /* Erase the secret before the frame is released or reused. */
    secure_wipe(entered, sizeof entered);

    return match;
}
