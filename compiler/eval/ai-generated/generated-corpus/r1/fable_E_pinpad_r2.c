#include <stddef.h>
#include <string.h>

#define PIN_LEN 6

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

/*
 * Wipe memory in a way the compiler cannot optimize away.
 * memset before a return on a dying stack object is legal to elide
 * under the as-if rule, so go through a volatile pointer.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int check_pin(void)
{
    char pin[PIN_LEN + 1];
    int ok;

    read_keypad(pin, sizeof pin);
    pin[PIN_LEN] = '\0';

    ok = stored_pin_equals(pin) ? 1 : 0;

    secure_wipe(pin, sizeof pin);

    return ok;
}
