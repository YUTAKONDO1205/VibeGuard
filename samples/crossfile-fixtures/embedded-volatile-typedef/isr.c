#include "shared.h"

reg_t tick_count = 0;

void timer_start(void)
{
  /* Board-specific timer bring-up elided. */
}

ISR(TIMER1_COMPA_vect)
{
  tick_count++;
}
