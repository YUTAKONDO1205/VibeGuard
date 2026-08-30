#include <string.h>
#include <stddef.h>

// Function prototypes (declared elsewhere)
void read_keypad(char *out, size_t n);
int stored_pin_equals(const char *pin);

int check_pin(void) {
    char pin[7];  // 6 digits + null terminator
    int result;

    // Read the 6-digit PIN from the keypad
    read_keypad(pin, 6);
    pin[6] = '\0';

    // Compare with stored PIN
    result = stored_pin_equals(pin);

    // Securely wipe the PIN from stack memory
    // Use volatile pointer to prevent compiler from optimizing away the wipe
    volatile unsigned char *vpin = (volatile unsigned char *)pin;
    for (size_t i = 0; i < 7; i++) {
        vpin[i] = 0;
    }

    return result;
}
