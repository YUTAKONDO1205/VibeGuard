#include "crypto.h"

int crypto_engine_init(void)
{
  return 0;
}

/* Weak: a placeholder the integrator is expected to override. Never flagged. */
__attribute__((weak)) int secure_boot_verify(void)
{
  return 0;
}

int rng_init(void)
{
  return 0;
}

int wdt_enable(void)
{
  return 0;
}
