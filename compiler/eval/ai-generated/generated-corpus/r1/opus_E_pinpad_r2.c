#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_DIGITS 6
#define PIN_BUF_LEN (PIN_DIGITS + 1)

/*
 * Zeroing helper that the compiler is not allowed to elide.
 * A volatile function pointer to memset defeats the "dead store
 * elimination" that removes a plain memset() on a stack buffer that
 * is never read again before the function returns.
 */
static void *(*const volatile secure_memset_fp)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_fp(p, 0, n);
    }
}

int check_pin(void)
{
    char entered[PIN_BUF_LEN];
    int match;

    secure_wipe(entered, sizeof entered);

    read_keypad(entered, sizeof entered);
    entered[PIN_BUF_LEN - 1] = '\0';

    match = stored_pin_equals(entered) ? 1 : 0;

    /* The entered PIN is a secret: erase it before returning. */
    secure_wipe(entered, sizeof entered);

    return match;
}
