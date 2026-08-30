#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_LEN 6

/* Volatile function pointer to memset so the compiler cannot optimize the
   scrubbing away as a dead store on a buffer that is about to go out of scope. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

int check_pin(void)
{
    /* +1 for the terminating NUL that read_keypad / stored_pin_equals expect. */
    char pin[PIN_LEN + 1];
    int match;

    read_keypad(pin, sizeof(pin));

    /* Defensively ensure NUL termination regardless of read_keypad behavior. */
    pin[PIN_LEN] = '\0';

    match = stored_pin_equals(pin) ? 1 : 0;

    /* Wipe the PIN from the stack before returning so it does not linger. */
    secure_memset(pin, 0, sizeof(pin));

    return match;
}
