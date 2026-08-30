#include <stddef.h>
#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

/*
 * PIN length is 6 digits. The stack buffer holds those 6 characters
 * plus a terminating NUL so the buffer can be treated as a C string.
 */
#define PIN_LEN 6
#define PIN_BUF_SIZE (PIN_LEN + 1)

/*
 * Secure zeroization that the compiler is not allowed to optimize away.
 * A plain memset() on a buffer that is not read afterwards is a classic
 * dead-store elimination target, which would leave the PIN on the stack.
 */
static void secure_wipe(volatile char *p, size_t n)
{
    while (n--) {
        *p++ = 0;
    }
}

int check_pin(void)
{
    char pin[PIN_BUF_SIZE];
    int result;

    /* Fill the whole buffer with a known state first. */
    secure_wipe((volatile char *)pin, sizeof pin);

    /*
     * Read exactly PIN_LEN digits into the buffer, leaving room for the
     * terminating NUL. read_keypad is told the number of digit slots to
     * fill; the last byte stays NUL so pin is always a valid C string and
     * cannot be over-run by stored_pin_equals.
     */
    read_keypad(pin, PIN_LEN);
    pin[PIN_LEN] = '\0';

    result = stored_pin_equals(pin) ? 1 : 0;

    /* Erase the entered PIN from the stack before returning. */
    secure_wipe((volatile char *)pin, sizeof pin);

    return result;
}
