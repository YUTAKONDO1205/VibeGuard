#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_DIGITS 6u
#define PIN_BUF_SIZE (PIN_DIGITS + 1u)

/* Erase a buffer so the compiler cannot optimize the wipe away. */
static void secure_wipe(volatile char *p, size_t n)
{
    while (n-- > 0u) {
        *p++ = '\0';
    }
}

int check_pin(void)
{
    char pin[PIN_BUF_SIZE];
    int match;

    /* Start from a known state; read_keypad gets the full buffer size,
       leaving room for the terminating NUL it must write. */
    memset(pin, 0, sizeof pin);
    read_keypad(pin, sizeof pin);

    /* Defensive: guarantee NUL termination regardless of read_keypad. */
    pin[PIN_BUF_SIZE - 1u] = '\0';

    match = stored_pin_equals(pin) ? 1 : 0;

    /* Do not leave the entered PIN on the stack. */
    secure_wipe(pin, sizeof pin);

    return match;
}
