#include <string.h>
#include <stddef.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

int check_pin(void) {
    char pin[7];
    int result;
    volatile char *vpin;

    read_keypad(pin, 6);
    result = stored_pin_equals(pin);

    vpin = (volatile char *)pin;
    memset((void *)vpin, 0, sizeof(pin));

    return result;
}
