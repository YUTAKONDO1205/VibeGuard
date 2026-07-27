#include <stdio.h>
#include <board_shared.h>

int main(void)
{
  unsigned long last = 0;

  timer_start();

  for (;;) {
    if (tick_count != last) {
      last = tick_count;
      printf("tick %lu\n", last);
    }
  }

  return 0;
}
