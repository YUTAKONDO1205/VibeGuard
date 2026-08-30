#include <stddef.h>
#include <string.h>

#define PIN_LEN 6

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

int check_pin(void)
{
    char entered[PIN_LEN + 1];
    int match;

    memset(entered, 0, sizeof(entered));

    read_keypad(entered, PIN_LEN);
    entered[PIN_LEN] = '\0';

    match = stored_pin_equals(entered) ? 1 : 0;

    return match;
}
