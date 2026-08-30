#include <string.h>

void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

static void secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *vp = (volatile unsigned char *)ptr;
    for (size_t i = 0; i < len; i++) {
        vp[i] = 0;
    }
}

int check_pin(void)
{
    char pin_buffer[7];

    read_keypad(pin_buffer, 6);
    pin_buffer[6] = '\0';

    int result = stored_pin_equals(pin_buffer);

    secure_zero(pin_buffer, sizeof(pin_buffer));

    return result;
}
