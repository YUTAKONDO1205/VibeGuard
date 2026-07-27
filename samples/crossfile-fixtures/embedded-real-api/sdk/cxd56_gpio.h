#ifndef CXD56_GPIO_H
#define CXD56_GPIO_H

/* A real API family: four declared members. */
int cxd56_gpio_config(int pin, int mode);
int cxd56_gpio_write(int pin, int value);
int cxd56_gpio_read(int pin);
int cxd56_gpio_deinit(int pin);

#endif
