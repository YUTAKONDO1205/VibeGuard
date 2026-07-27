#include <stdio.h>
#include "legacy/board.h"

int main(void)
{
  uint32_t last = 0;

  for (;;) {
    if (tick_count != last) {
      last = tick_count;
      printf("tick %lu\n", (unsigned long)last);
    }
  }

  return 0;
}
