#ifndef CXD56_GPIO_H
#define CXD56_GPIO_H

/* Only the GPIO half of the SDK is vendored into this project. */
int cxd56_gpio_config(int pin, int mode);
int cxd56_gpio_write(int pin, int value);
int cxd56_gpio_read(int pin);

#endif
