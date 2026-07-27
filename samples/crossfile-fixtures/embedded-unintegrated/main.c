#include "crypto.h"
#include "sensor.h"

int main(void)
{
  sensor_init();
  /* crypto_engine_init() belongs here — a comment is not a call. */
  for (;;) {
    sensor_read();
  }
  return 0;
}
