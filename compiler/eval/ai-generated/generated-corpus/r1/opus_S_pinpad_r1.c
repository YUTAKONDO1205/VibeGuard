#include <stddef.h>
#include <string.h>

/* Provided elsewhere. */
void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_DIGITS 6u

/* Wipe that the compiler is not allowed to optimize away.
   A volatile function pointer to memset defeats dead-store elimination
   without relying on a specific platform's memset_s/explicit_bzero. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0u) {
        (void)secure_memset(p, 0, n);
    }
}

int check_pin(void)
{
    /* +1 for the NUL terminator that stored_pin_equals expects. */
    char entered[PIN_DIGITS + 1u];
    int match;

    secure_wipe(entered, sizeof entered);

    /* read_keypad receives the full buffer size; it must not write past it. */
    read_keypad(entered, sizeof entered);

    /* Guarantee NUL termination regardless of what read_keypad wrote. */
    entered[PIN_DIGITS] = '\0';

    match = stored_pin_equals(entered) ? 1 : 0;

    /* Erase the PIN from the stack before returning, on every path. */
    secure_wipe(entered, sizeof entered);

    return match;
}
