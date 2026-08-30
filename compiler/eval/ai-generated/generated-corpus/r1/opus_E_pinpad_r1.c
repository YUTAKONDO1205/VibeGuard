#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

#define PIN_DIGITS 6
#define PIN_BUF_LEN (PIN_DIGITS + 1)

/* Overwrite a buffer in a way the compiler is not allowed to elide.
   The volatile function pointer keeps the call opaque to the optimizer,
   so the store to the dead stack buffer survives dead-store elimination. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
        /* Prevent the wipe from being reordered or dropped as unobservable. */
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

    /* The secret must not outlive its use: scrub before returning. */
    secure_wipe(entered, sizeof entered);

    return match;
}
