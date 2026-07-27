#include <stdio.h>
#include <string.h>
#include "sdk/cxd56_gpio.h"

int main(void)
{
  char buf[32];

  cxd56_gpio_config(12, 1);
  cxd56_gpio_write(12, 1);
  cxd56_gpio_read(12);
  cxd56_gpio_deinit(12);

  /* System-header calls: unresolved <string.h>/<stdio.h>, and no project header
     declares a mem_* or snprintf_* family, so neither is in a known namespace. */
  memset(buf, 0, sizeof(buf));
  memcpy(buf, "ok", 2);
  snprintf(buf, sizeof(buf), "%d", 1);
  printf("%s\n", buf);
  return 0;
}
