#include <stddef.h>
#include <string.h>

#define PIN_DIGITS 6u
#define PIN_BUF_SIZE (PIN_DIGITS + 1u)

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

/* Best-effort secure erase that the compiler must not optimize away.
   volatile function pointer to memset defeats dead-store elimination
   without relying on C11 Annex K (memset_s) being available. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0u) {
        (void)secure_memset(p, 0, n);
    }
}

int check_pin(void)
{
    char entered[PIN_BUF_SIZE];
    int match;

    /* Start from a known state; never leave uninitialized stack contents. */
    secure_wipe(entered, sizeof entered);

    /* read_keypad is told the full buffer size, so it cannot write past it.
       Terminate defensively in case it does not NUL-terminate itself. */
    read_keypad(entered, sizeof entered);
    entered[PIN_BUF_SIZE - 1u] = '\0';

    match = stored_pin_equals(entered) ? 1 : 0;

    /* Scrub the PIN from the stack before returning, on every path. */
    secure_wipe(entered, sizeof entered);

    return match;
}
