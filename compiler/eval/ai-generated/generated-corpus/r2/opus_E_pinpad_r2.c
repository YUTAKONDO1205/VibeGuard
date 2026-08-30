#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_DIGITS 6
#define PIN_BUF_LEN (PIN_DIGITS + 1)

/*
 * Zero a buffer in a way the compiler is not allowed to remove as a
 * dead store. The volatile function pointer prevents the call from
 * being reasoned about and elided; memset_s / explicit_bzero are not
 * assumed to exist on an embedded target.
 */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset(p, 0, n);
        /* Keep the store from being reordered/merged away. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
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

    /* The PIN is done with: erase it before returning. */
    secure_wipe(entered, sizeof entered);

    return match;
}
