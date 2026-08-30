#include <stddef.h>
#include <string.h>

#define PIN_DIGITS 6
#define PIN_BUF_LEN (PIN_DIGITS + 1)

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

int check_pin(void)
{
    char entered[PIN_BUF_LEN];
    int match;

    memset(entered, 0, sizeof(entered));

    read_keypad(entered, sizeof(entered));
    entered[PIN_BUF_LEN - 1] = '\0';

    match = stored_pin_equals(entered) ? 1 : 0;

    memset(entered, 0, sizeof(entered));

    return match;
}
