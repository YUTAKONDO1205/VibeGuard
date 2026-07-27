#include "crypto.h"

/* Generated correctly, and never wired into the start-up path. */
int crypto_engine_init(void)
{
  volatile unsigned int *reg = (unsigned int *)0x40010000;
  *reg = 1u;
  return 0;
}
