#include "crypto.h"

typedef int (*init_fn)(void);

/* Wired by function pointer in a callback table — never a syntactic call. */
static const init_fn startup_table[] = {
  crypto_engine_init,
};

struct driver {
  int (*init)(void);
};

/* Wired by designated initialiser. */
static const struct driver rng_driver = {
  .init = rng_init,
};

extern void xTaskCreate(void (*fn)(void), const char *name, int stack);

void register_tasks(void)
{
  /* Wired by RTOS task registration — the address is taken, never called here. */
  xTaskCreate((void (*)(void))wdt_enable, "wdt", 256);
}
