#include <board_shared.h>

void timer_start(void)
{
  /* Board-specific timer bring-up elided. */
}

ISR(TIMER1_COMPA_vect)
{
  tick_count++;
}
