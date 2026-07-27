#include <stdio.h>
#include "sdk/cxd56_gpio.h"

#define LED_PIN 12

int main(void)
{
  cxd56_gpio_config(LED_PIN, 1);
  cxd56_gpio_write(LED_PIN, 1);

  /* Does not exist. Spelled exactly like the real members above. */
  cxd56_gpio_toggle(LED_PIN);

  printf("done\n");
  return 0;
}
