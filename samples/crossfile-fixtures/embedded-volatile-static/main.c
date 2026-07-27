#include <stdio.h>
#include "shared.h"

int main(void)
{
  uint32_t last = 0;

  timer_start();

  for (;;) {
    if (tick_count != last) {
      last = tick_count;
      printf("tick %lu\n", (unsigned long)last);
    }
  }

  return 0;
}
