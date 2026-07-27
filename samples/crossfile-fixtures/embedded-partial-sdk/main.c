#include "sdk/cxd56_gpio.h"
#include <cxd56_pwm.h>
#include <cxd56_adc.h>

int main(void)
{
  cxd56_gpio_config(1, 1);
  cxd56_gpio_write(1, 1);

  /* Real SDK functions. Their headers are angled and legitimately unscanned. */
  cxd56_pwm_start(0, 1000);
  cxd56_adc_read(2);
  return 0;
}
